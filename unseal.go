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
	"github.com/canonical/go-tpm2"
	"github.com/snapcore/secboot/internal/tcg"

	"golang.org/x/xerrors"
)

// UnsealFromTPM will load the TPM sealed object in to the TPM and attempt to unseal it, returning the cleartext key on success.
// If a PIN has been set, the correct PIN must be provided via the pin argument. If the wrong PIN is provided, a ErrPINFail error
// will be returned, and the TPM's dictionary attack counter will be incremented.
//
// If the TPM's dictionary attack logic has been triggered, a ErrTPMLockout error will be returned.
//
// If the TPM is not provisioned correctly, then a ErrTPMProvisioning error will be returned. In this case, ProvisionTPM should be
// called to attempt to resolve this.
//
// If the TPM sealed object cannot be loaded in to the TPM for reasons other than the lack of a storage root key, then a
// InvalidKeyDataError error will be returned with RetryProvision set to true. This could be caused because the sealed object data
// is invalid in some way, or because the TPM object at the persistent handle reserved for the storage root key is not
// the creation parent of the TPM sealed object. In the latter case, it may be possible to recover access to the sealed key by
// calling ProvisionTPM again as long as the TPM owner hasn't changed (ie, the TPM has not been cleared).
//
// If the TPM's current PCR values are not consistent with the PCR protection policy for this key object, a InvalidPolicyDataError
// error will be returned.
//
// If any of the metadata in this key object is invalid, or if the TPM is missing any persistent resources associated with this key
// object, a InvalidKeyDataError error will be returned. In this case, there isn't a way to recover this key.
//
// If the PCR policy has been superceded (eg, by a call to UpdateKeyPCRProtectionPolicy), then a InvalidPolicyDataError error will be
// returned.
//
// If the signature of the key object's authorized PCR policy or any metadata associated with it is invalid, then a
// InvalidPolicyDataError error will be returned.
//
// If the PCR policy is not consistent with the current PCR values, then a InvalidPolicyDataError error will be returned.
//
// If the provided PIN is incorrect, then a ErrPINFail error will be returned and the TPM's dictionary attack counter will be
// incremented.
//
// If access to sealed key objects created by this package is disallowed until the next TPM reset or TPM restart, then a
// ErrSealedKeyAccessLocked error will be returned.
//
// If the authorization policy check fails during unsealing, then a InvalidKeyDataError error will be returned.
//
// On success, the unsealed cleartext key is returned as the first return value, and the private part of the key used for
// authorizing PCR policy updates with UpdateKeyPCRProtectionPolicy is returned as the second return value.
func (k *SealedKeyObject) UnsealFromTPM(tpm *TPMConnection, pin string) (key []byte, authKey TPMPolicyAuthKey, err error) {
	c, err := k.BeginUnsealFromTPM(tpm)
	if err != nil {
		return nil, nil, err
	}

	return c.UnsealWithPCRPolicy(pin)
}

type UnsealFromTPMContext struct {
	tpm           *TPMConnection
	data          *keyData
	key           tpm2.ResourceContext
	policySession tpm2.SessionContext
}

func (c *UnsealFromTPMContext) FlushContexts() {
	c.tpm.FlushContext(c.key)
	c.tpm.FlushContext(c.policySession)
}

func (c *UnsealFromTPMContext) NonceTPM() tpm2.Nonce {
	return c.policySession.NonceTPM()
}

func (c *UnsealFromTPMContext) unseal(pin string) ([]byte, TPMPolicyAuthKey, error) {
	// For metadata version > 0, the PIN is the auth value for the sealed key object, and the authorization
	// policy asserts that this value is known when the policy session is used.
	c.key.SetAuthValue([]byte(pin))

	// Unseal
	keyData, err := c.tpm.Unseal(c.key, c.policySession, c.tpm.HmacSession().IncludeAttrs(tpm2.AttrResponseEncrypt))
	switch {
	case tpm2.IsTPMSessionError(err, tpm2.ErrorPolicyFail, tpm2.CommandUnseal, 1):
		// We could get here if some of the metadata required to execute the policy session is invalid
		// (eg, staticPolicyData.AuthPublicKey) or if lockNVHandle has a name that is different to the
		// one that existed when the key was sealed.
		return nil, nil, InvalidKeyDataError{RetryProvision: false, msg: "the authorization policy check failed during unsealing"}
	case isAuthFailError(err, tpm2.CommandUnseal, 1):
		return nil, nil, ErrPINFail
	case tpm2.IsTPMWarning(err, tpm2.WarningLockout, tpm2.CommandUnseal):
		return nil, nil, ErrTPMLockout
	case err != nil:
		return nil, nil, xerrors.Errorf("cannot unseal key: %w", err)
	}

	if c.data.version == 0 {
		return keyData, nil, nil
	}

	var sealedData sealedData
	if _, err := tpm2.UnmarshalFromBytes(keyData, &sealedData); err != nil {
		return nil, nil, InvalidKeyDataError{RetryProvision: false, msg: err.Error()}
	}

	return sealedData.Key, sealedData.AuthPrivateKey, nil
}

func (c *UnsealFromTPMContext) UnsealWithPCRPolicy(pin string) ([]byte, TPMPolicyAuthKey, error) {
	defer c.FlushContexts()

	if err := c.data.pcrPolicyData.execute(c.tpm.TPMContext, c.policySession, c.data.version, c.data.staticPolicyData, pin, c.tpm.HmacSession()); err != nil {
		err = xerrors.Errorf("cannot complete authorization policy assertions: %w", err)
		switch {
		case isKeyDataError(err):
			return nil, nil, InvalidKeyDataError{RetryProvision: false, msg: err.Error()}
		case isPolicyDataError(err):
			return nil, nil, InvalidPolicyDataError(err.Error())
		case isAuthFailError(err, tpm2.CommandPolicySecret, 1):
			return nil, nil, ErrPINFail
		case tpm2.IsTPMWarning(err, tpm2.WarningLockout, tpm2.CommandPolicySecret):
			return nil, nil, ErrTPMLockout
		case tpm2.IsResourceUnavailableError(err, c.data.staticPolicyData.pcrPolicyCounterHandle):
			return nil, nil, InvalidKeyDataError{RetryProvision: false, msg: "no PCR policy counter found"}
		case tpm2.IsResourceUnavailableError(err, lockNVHandle):
			// This is technically a provisioning error, but the current index can't be recreated. This key
			// can never be recovered even after re-provisioning.
			return nil, nil, InvalidKeyDataError{RetryProvision: false, msg: "a required NV index is missing from the TPM"}
		case tpm2.IsTPMError(err, tpm2.ErrorNVLocked, tpm2.CommandPolicyNV):
			return nil, nil, ErrSealedKeyAccessLocked
		}
		return nil, nil, err
	}

	return c.unseal(pin)
}

func (c *UnsealFromTPMContext) UnsealWithRecoveryAuth(publicKey *tpm2.Public, signature *tpm2.Signature, pin string) ([]byte, TPMPolicyAuthKey, error) {
	defer c.FlushContexts()

	if c.data.recoveryPolicyData == nil {
		return nil, nil, InvalidKeyDataError{RetryProvision: false, msg: "no recovery policy data"}
	}

	if err := c.data.recoveryPolicyData.execute(c.tpm.TPMContext, c.policySession, c.data.staticPolicyData, publicKey, signature); err != nil {
		err = xerrors.Errorf("cannot complete authorization policy assertions: %w", err)
		switch {
		case isKeyDataError(err):
			return nil, nil, InvalidKeyDataError{RetryProvision: false, msg: err.Error()}
		case isPolicyDataError(err):
			return nil, nil, InvalidPolicyDataError(err.Error())
		}
		return nil, nil, err
	}

	return c.unseal(pin)
}

func (k *SealedKeyObject) BeginUnsealFromTPM(tpm *TPMConnection) (*UnsealFromTPMContext, error) {
	// Load the key data
	keyObject, err := k.data.load(tpm.TPMContext, tpm.HmacSession())
	switch {
	case tpm2.IsResourceUnavailableError(err, tcg.SRKHandle):
		return nil, ErrTPMProvisioning
	case xerrors.Is(err, errInvalidTPMSealedObject):
		return nil, InvalidKeyDataError{RetryProvision: true, msg: err.Error()}
	case err != nil:
		return nil, xerrors.Errorf("cannot load sealed key in to TPM: %w", err)
	}

	// Begin and execute policy session
	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, k.data.keyPublic.NameAlg)
	if err != nil {
		return nil, xerrors.Errorf("cannot start policy session: %w", err)
	}

	return &UnsealFromTPMContext{
		tpm:           tpm,
		data:          k.data,
		key:           keyObject,
		policySession: policySession}, nil
}
