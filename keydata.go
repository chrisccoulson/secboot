// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package secboot

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/chrisccoulson/go-tpm2"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/osutil/sys"

	"golang.org/x/xerrors"
)

const (
	currentVersion       uint32 = 0
	keyDataHeader        uint32 = 0x55534b24
	privateKeyDataHeader uint32 = 0x55534b50
)

// AuthMode corresponds to an authentication mechanism.
type AuthMode uint8

const (
	AuthModeNone AuthMode = iota
	AuthModePIN
)

// privateKeyData corresponds to the private part of a sealed key object that is required in order to create new dynamic
// authorization policies.
type privateKeyData struct {
	Data struct {
		AuthKey []byte
	}
	CreationData   *tpm2.CreationData
	CreationTicket *tpm2.TkCreation
}

// keyData corresponds to the part of a sealed key object that contains the TPM sealed object and associated metadata required
// for executing authorization policy assertions.
type keyData struct {
	KeyPrivate        tpm2.Private
	KeyPublic         *tpm2.Public
	AuthModeHint      AuthMode
	StaticPolicyData  *staticPolicyData
	DynamicPolicyData *dynamicPolicyData
}

// readPrivateData deserializes privateKeyData from the provided io.Reader.
func readPrivateData(buf io.Reader) (*privateKeyData, error) {
	var header uint32
	var version uint32
	if err := tpm2.UnmarshalFromReader(buf, &header, &version); err != nil {
		return nil, xerrors.Errorf("cannot unmarshal header and version number: %w", err)
	}

	if header != privateKeyDataHeader {
		return nil, fmt.Errorf("unexpected header (%d)", header)
	}
	if version != currentVersion {
		return nil, fmt.Errorf("unexpected version number (%d)", version)
	}

	var d privateKeyData
	if err := tpm2.UnmarshalFromReader(buf, &d); err != nil {
		return nil, xerrors.Errorf("cannot unmarshal key data: %w", err)
	}

	return &d, nil
}

// write serializes privateKeyData to the provided io.Writer.
func (d *privateKeyData) write(buf io.Writer) error {
	return tpm2.MarshalToWriter(buf, privateKeyDataHeader, currentVersion, d)
}

type keyFileError struct {
	err error
}

func (e keyFileError) Error() string {
	return e.err.Error()
}

// readKeyData deserializes keyData from the provided io.Reader.
func readKeyData(buf io.Reader) (*keyData, error) {
	var header uint32
	var version uint32
	if err := tpm2.UnmarshalFromReader(buf, &header, &version); err != nil {
		return nil, keyFileError{xerrors.Errorf("cannot unmarshal header and version number: %w", err)}
	}

	if header != keyDataHeader {
		return nil, keyFileError{fmt.Errorf("unexpected header (%d)", header)}
	}
	if version != currentVersion {
		return nil, keyFileError{fmt.Errorf("unexpected version number (%d)", version)}
	}

	var d keyData
	if err := tpm2.UnmarshalFromReader(buf, &d); err != nil {
		return nil, keyFileError{xerrors.Errorf("cannot unmarshal key data: %w", err)}
	}

	return &d, nil
}

// load loads the TPM sealed object associated with this keyData in to the storage hierarchy of the TPM, and returns the newly
// created tpm2.ResourceContext.
func (d *keyData) load(tpm *tpm2.TPMContext, session tpm2.SessionContext) (tpm2.ResourceContext, error) {
	srkContext, err := tpm.CreateResourceContextFromTPM(srkHandle)
	if err != nil {
		return nil, xerrors.Errorf("cannot create context for SRK: %w", err)
	}

	keyContext, err := tpm.Load(srkContext, d.KeyPrivate, d.KeyPublic, session)
	if err != nil {
		invalidObject := false
		switch e := err.(type) {
		case *tpm2.TPMParameterError:
			_ = e
			invalidObject = true
		case *tpm2.TPMError:
			if e.Code == tpm2.ErrorSensitive {
				invalidObject = true
			}
		}
		if invalidObject {
			return nil, keyFileError{errors.New("cannot load sealed key object in to TPM: bad sealed key object or TPM owner changed")}
		}
		return nil, xerrors.Errorf("cannot load sealed key object in to TPM: %w", err)
	}

	return keyContext, nil
}

// write serializes keyData in to the provided io.Writer.
func (d *keyData) write(buf io.Writer) error {
	return tpm2.MarshalToWriter(buf, keyDataHeader, currentVersion, d)
}

// writeToFileAtomic serializes keyData and writes it atomically to the file at the specified path.
func (d *keyData) writeToFileAtomic(dest string) error {
	f, err := osutil.NewAtomicFile(dest, 0600, 0, sys.UserID(osutil.NoChown), sys.GroupID(osutil.NoChown))
	if err != nil {
		return xerrors.Errorf("cannot create new atomic file: %w", err)
	}
	defer f.Cancel()

	if err := tpm2.MarshalToWriter(f, keyDataHeader, currentVersion, d); err != nil {
		return xerrors.Errorf("cannot marshal key data to temporary file: %w", err)
	}

	if err := f.Commit(); err != nil {
		return xerrors.Errorf("cannot atomically replace file: %w", err)
	}

	return nil
}

// validateKeyData performs some correctness checking on the provided keyData and privateKeyData. On success, it returns the validated
// public area for the PIN NV index.
func validateKeyData(tpm *tpm2.TPMContext, data *keyData, privateData *privateKeyData, session tpm2.SessionContext) (*tpm2.NVPublic, error) {
	srkContext, err := tpm.CreateResourceContextFromTPM(srkHandle)
	if err != nil {
		return nil, xerrors.Errorf("cannot create context for SRK: %w", err)
	}

	// Perform some initial checks on the sealed data object's public area
	if data.KeyPublic.Type != tpm2.ObjectTypeKeyedHash {
		return nil, keyFileError{errors.New("sealed key object has the wrong type")}
	}
	if data.KeyPublic.Attrs != (tpm2.AttrFixedTPM | tpm2.AttrFixedParent) {
		return nil, keyFileError{errors.New("sealed key object has the wrong attributes")}
	}

	// Load the sealed data object in to the TPM for integrity checking
	keyContext, err := tpm.Load(srkContext, data.KeyPrivate, data.KeyPublic, session)
	if err != nil {
		invalidObject := false
		switch e := err.(type) {
		case *tpm2.TPMParameterError:
			_ = e
			invalidObject = true
		case *tpm2.TPMError:
			if e.Code == tpm2.ErrorSensitive {
				invalidObject = true
			}
		}
		if invalidObject {
			return nil, keyFileError{errors.New("cannot load sealed key object in to TPM: bad sealed key object or TPM owner changed")}
		}
		return nil, xerrors.Errorf("cannot load sealed key object in to TPM: %w", err)
	}
	// It's loaded ok, so we know that the private and public parts are consistent.
	defer tpm.FlushContext(keyContext)

	lockIndex, err := tpm.CreateResourceContextFromTPM(lockNVHandle)
	if err != nil {
		return nil, xerrors.Errorf("cannot create context for lock NV index: %v", err)
	}
	lockIndexPub, err := readAndValidateLockNVIndexPublic(tpm, lockIndex, session)
	if err != nil {
		return nil, xerrors.Errorf("cannot determine if NV index at 0x%08x is global lock index: %w", lockNVHandle, err)
	}
	if lockIndexPub == nil {
		return nil, xerrors.Errorf("NV index at 0x%08x is not a valid global lock index", lockNVHandle)
	}

	// Obtain a ResourceContext for the PIN NV index. Go-tpm2 calls TPM2_NV_ReadPublic twice here. The second time is with a session, and
	// there is also verification that the returned public area is for the specified handle so that we know that the returned
	// ResourceContext corresponds to an actual entity on the TPM at PinIndexHandle.
	if data.StaticPolicyData.PinIndexHandle.Type() != tpm2.HandleTypeNVIndex {
		return nil, keyFileError{errors.New("PIN NV index handle is invalid")}
	}
	pinIndex, err := tpm.CreateResourceContextFromTPM(data.StaticPolicyData.PinIndexHandle, session.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		if isResourceUnavailableError(err) {
			return nil, keyFileError{errors.New("PIN NV index is unavailable")}
		}
		return nil, xerrors.Errorf("cannot create context for PIN NV index: %w", err)
	}

	authKeyName, err := data.StaticPolicyData.AuthPublicKey.Name()
	if err != nil {
		return nil, keyFileError{xerrors.Errorf("cannot compute name of dynamic authorization policy key: %w", err)}
	}
	if data.StaticPolicyData.AuthPublicKey.Type != tpm2.ObjectTypeRSA {
		return nil, keyFileError{errors.New("public area of dynamic authorization policy signing key has the wrong type")}
	}

	// Make sure that the static authorization policy data is consistent with the sealed key object's policy.
	trial, err := tpm2.ComputeAuthPolicy(data.KeyPublic.NameAlg)
	if err != nil {
		return nil, keyFileError{xerrors.Errorf("cannot determine if static authorization policy matches sealed key object: %w", err)}
	}
	trial.PolicyAuthorize(nil, authKeyName)
	trial.PolicySecret(pinIndex.Name(), nil)
	trial.PolicyNV(lockIndex.Name(), nil, 0, tpm2.OpEq)

	if !bytes.Equal(trial.GetDigest(), data.KeyPublic.AuthPolicy) {
		return nil, keyFileError{errors.New("the sealed key object's authorization policy is inconsistent with the associatedc metadata or persistent TPM resources")}
	}

	pinIndexPublic, _, err := tpm.NVReadPublic(pinIndex, session.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		return nil, xerrors.Errorf("cannot read public area of PIN NV index: %w", err)
	}

	expectedPinIndexAuthPolicies, err := computePinNVIndexPostInitAuthPolicies(pinIndexPublic.NameAlg, authKeyName)
	if err != nil {
		return nil, keyFileError{xerrors.Errorf("cannot determine if PIN NV index has a valid authorization policy: %w", err)}
	}
	if len(data.StaticPolicyData.PinIndexAuthPolicies)-1 != len(expectedPinIndexAuthPolicies) {
		return nil, keyFileError{errors.New("unexpected number of OR policy digests for PIN NV index")}
	}
	for i, expected := range expectedPinIndexAuthPolicies {
		if !bytes.Equal(expected, data.StaticPolicyData.PinIndexAuthPolicies[i+1]) {
			return nil, keyFileError{errors.New("unexpected OR policy digest for PIN NV index")}
		}
	}

	trial, _ = tpm2.ComputeAuthPolicy(pinIndexPublic.NameAlg)
	trial.PolicyOR(data.StaticPolicyData.PinIndexAuthPolicies)
	if !bytes.Equal(pinIndexPublic.AuthPolicy, trial.GetDigest()) {
		return nil, keyFileError{errors.New("PIN NV index has unexpected authorization policy")}
	}

	// At this point, we know that the sealed object is an object with an authorization policy created by this package and with
	// matching static metadata and persistent TPM resources.

	if privateData == nil {
		// If we weren't passed a private data structure, we're done.
		return pinIndexPublic, nil
	}

	// Verify that the private data structure is bound to the key data structure.
	h := data.KeyPublic.NameAlg.NewHash()
	if err := tpm2.MarshalToWriter(h, privateData.CreationData); err != nil {
		panic(fmt.Sprintf("cannot marshal creation data: %v", err))
	}

	if _, _, err := tpm.CertifyCreation(nil, keyContext, nil, h.Sum(nil), nil, privateData.CreationTicket, nil,
		session.IncludeAttrs(tpm2.AttrAudit)); err != nil {
		switch e := err.(type) {
		case *tpm2.TPMParameterError:
			if e.Index == 4 {
				return nil, keyFileError{errors.New("key data file and private data file mismatch: invalid creation ticket")}
			}
		}
		return nil, xerrors.Errorf("cannot validate creation data for sealed data object: %w", err)
	}

	h = crypto.SHA256.New()
	if err := tpm2.MarshalToWriter(h, &privateData.Data); err != nil {
		panic(fmt.Sprintf("cannot marshal private data: %v", err))
	}

	if !bytes.Equal(h.Sum(nil), privateData.CreationData.OutsideInfo) {
		return nil, keyFileError{errors.New("key data file and private data file mismatch: digest doesn't match creation data")}
	}

	authKey, err := x509.ParsePKCS1PrivateKey(privateData.Data.AuthKey)
	if err != nil {
		return nil, keyFileError{xerrors.Errorf("cannot parse dynamic policy authorization key: %w", err)}
	}

	authPublicKey := rsa.PublicKey{
		N: new(big.Int).SetBytes(data.StaticPolicyData.AuthPublicKey.Unique.RSA()),
		E: int(data.StaticPolicyData.AuthPublicKey.Params.RSADetail().Exponent)}
	if authKey.PublicKey.E != authPublicKey.E || authKey.PublicKey.N.Cmp(authPublicKey.N) != 0 {
		return nil, keyFileError{errors.New("dynamic authorization policy signing private key doesn't match public key")}
	}

	return pinIndexPublic, nil
}

// readAndValidateKeyData will deserialize keyData and privateKeyData from the provided io.Readers and then perform some correctness
// checking. On success, it returns the keyData, privateKeyData and the validated public area of the PIN NV index.
func readAndValidateKeyData(tpm *tpm2.TPMContext, keyFile, privateFile io.Reader, session tpm2.SessionContext) (*keyData, *privateKeyData, *tpm2.NVPublic, error) {
	// Read the key data
	data, err := readKeyData(keyFile)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot read key data: %w", err)
	}

	var privateData *privateKeyData
	if privateFile != nil {
		var err error
		privateData, err = readPrivateData(privateFile)
		if err != nil {
			return nil, nil, nil, xerrors.Errorf("cannot read private data file: %w", err)
		}
	}

	pinNVPublic, err := validateKeyData(tpm, data, privateData, session)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("key data validation failed: %w", err)
	}

	return data, privateData, pinNVPublic, nil
}
