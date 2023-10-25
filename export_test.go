// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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
	"encoding/json"
	"io"
	"math/rand"

	"github.com/snapcore/secboot/internal/luks2"
	"github.com/snapcore/secboot/internal/luksview"
	"golang.org/x/xerrors"
)

var (
	UnmarshalV1KeyPayload  = unmarshalV1KeyPayload
	UnmarshalProtectedKeys = unmarshalProtectedKeys
)

func (o *KDFOptions) DeriveCostParams(keyLen int, kdf KDF) (*KDFCostParams, error) {
	return o.deriveCostParams(keyLen, kdf)
}

func MockLUKS2Activate(fn func(string, string, []byte, int) error) (restore func()) {
	origActivate := luks2Activate
	luks2Activate = fn
	return func() {
		luks2Activate = origActivate
	}
}

func MockLUKS2AddKey(fn func(string, []byte, []byte, *luks2.AddKeyOptions) error) (restore func()) {
	origAddKey := luks2AddKey
	luks2AddKey = fn
	return func() {
		luks2AddKey = origAddKey
	}
}

func MockLUKS2Deactivate(fn func(string) error) (restore func()) {
	origDeactivate := luks2Deactivate
	luks2Deactivate = fn
	return func() {
		luks2Deactivate = origDeactivate
	}
}

func MockLUKS2Format(fn func(string, string, []byte, *luks2.FormatOptions) error) (restore func()) {
	origFormat := luks2Format
	luks2Format = fn
	return func() {
		luks2Format = origFormat
	}
}

func MockLUKS2ImportToken(fn func(string, luks2.Token, *luks2.ImportTokenOptions) error) (restore func()) {
	origImportToken := luks2ImportToken
	luks2ImportToken = fn
	return func() {
		luks2ImportToken = origImportToken
	}
}

func MockLUKS2KillSlot(fn func(string, int, []byte) error) (restore func()) {
	origKillSlot := luks2KillSlot
	luks2KillSlot = fn
	return func() {
		luks2KillSlot = origKillSlot
	}
}

func MockLUKS2RemoveToken(fn func(string, int) error) (restore func()) {
	origRemoveToken := luks2RemoveToken
	luks2RemoveToken = fn
	return func() {
		luks2RemoveToken = origRemoveToken
	}
}

func MockLUKS2SetSlotPriority(fn func(string, int, luks2.SlotPriority) error) (restore func()) {
	origSetSlotPriority := luks2SetSlotPriority
	luks2SetSlotPriority = fn
	return func() {
		luks2SetSlotPriority = origSetSlotPriority
	}
}

func MockNewLUKSView(fn func(string, luks2.LockMode) (*luksview.View, error)) (restore func()) {
	origNewLUKSView := newLUKSView
	newLUKSView = fn
	return func() {
		newLUKSView = origNewLUKSView
	}
}

func MockRuntimeNumCPU(n int) (restore func()) {
	orig := runtimeNumCPU
	runtimeNumCPU = func() int {
		return n
	}
	return func() {
		runtimeNumCPU = orig
	}
}

func MockStderr(w io.Writer) (restore func()) {
	orig := osStderr
	osStderr = w
	return func() {
		osStderr = orig
	}
}

// MockReadKeyData is used to create legacy v1 keys from
// v2 keys by changing their version.
func MockReadKeyData(version int) (restore func()) {
	origReadKeyData := ReadKeyData
	ReadKeyData = func(r KeyDataReader) (*KeyData, error) {
		d := &KeyData{readableName: r.ReadableName()}
		dec := json.NewDecoder(r)
		if err := dec.Decode(&d.data); err != nil {
			return nil, xerrors.Errorf("cannot decode key data: %w", err)
		}

		d.data.Version = version

		return d, nil

	}
	return func() {
		ReadKeyData = origReadKeyData
	}
}

// MockMakeDiskUnlockKey uses the new keydata API but creates v1 keydata payloads.
func MockMakeDiskUnlockKey(primaryKey PrimaryKey) (func(), error) {
	origMakeDiskUnlockKey := MakeDiskUnlockKey
	MakeDiskUnlockKey = func(rand io.Reader, alg crypto.Hash, primaryKey PrimaryKey) (unlockKey DiskUnlockKey, clearTextPayload []byte, err error) {

		unique := make([]byte, len(primaryKey))
		_, err = rand.Read(unique)
		if err != nil {
			return nil, nil, err
		}

		reader := new(bytes.Buffer)
		reader.Write(unique)

		unlockKey, _, err = origMakeDiskUnlockKey(reader, crypto.SHA256, primaryKey)
		if err != nil {
			return nil, nil, err
		}

		clearTextPayload = MarshalKeys(unlockKey, primaryKey)
		return unlockKey, clearTextPayload, err
	}
	return func() {
		MakeDiskUnlockKey = origMakeDiskUnlockKey
	}, nil

}

// MockNewKeyData creates v1 keyData objects that implement the legacy HMAC behaviour
// for the verification of authorized snap models.
func MockNewKeyData(auxKey PrimaryKey, unlockKey DiskUnlockKey) (restore func()) {
	origNewKeyData := NewKeyData
	NewKeyData = func(params *KeyParams) (*KeyData, error) {
		encodedHandle, err := json.Marshal(params.Handle)
		if err != nil {
			return nil, xerrors.Errorf("cannot encode platform handle: %w", err)
		}

		var salt [32]byte
		if _, err := rand.Read(salt[:]); err != nil {
			return nil, xerrors.Errorf("cannot read salt: %w", err)
		}

		snapModelAuthHash := crypto.SHA256

		kd := &KeyData{
			data: keyData{
				Version:          1,
				PlatformName:     params.PlatformName,
				PlatformHandle:   json.RawMessage(encodedHandle),
				EncryptedPayload: params.EncryptedPayload,
				KDFAlg:           hashAlg(crypto.SHA256),
				AuthorizedSnapModels: &authorizedSnapModels{
					alg:    hashAlg(snapModelAuthHash),
					kdfAlg: hashAlg(snapModelAuthHash),
					keyDigest: keyDigest{
						Alg:  hashAlg(snapModelAuthHash),
						Salt: salt[:]}}}}

		authKey, err := kd.snapModelHMACKey(auxKey)
		if err != nil {
			return nil, xerrors.Errorf("cannot compute snap model auth key: %w", err)
		}

		h := kd.data.AuthorizedSnapModels.keyDigest.Alg.New()
		h.Write(authKey)
		h.Write(kd.data.AuthorizedSnapModels.keyDigest.Salt)
		kd.data.AuthorizedSnapModels.keyDigest.Digest = h.Sum(nil)

		return kd, nil

	}
	return func() {
		NewKeyData = origNewKeyData
	}
}
