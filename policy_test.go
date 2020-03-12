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

package secboot_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"sort"
	"testing"

	"github.com/chrisccoulson/go-tpm2"
	. "github.com/snapcore/secboot"

	"golang.org/x/xerrors"
)

func validateLockNVIndex(t *testing.T, tpm *tpm2.TPMContext) {
	index, err := tpm.CreateResourceContextFromTPM(LockNVHandle)
	if err != nil {
		t.Fatalf("Cannot create context for lock NV index: %v", err)
	}

	// Validate the properties of the index
	pub, _, err := tpm.NVReadPublic(index)
	if err != nil {
		t.Fatalf("NVReadPublic failed: %v", err)
	}

	if pub.NameAlg != tpm2.HashAlgorithmSHA256 {
		t.Errorf("Lock NV index has the wrong name algorithm")
	}
	if pub.Attrs.Type() != tpm2.NVTypeOrdinary {
		t.Errorf("Lock NV index has the wrong type")
	}
	if pub.Attrs.AttrsOnly() != tpm2.AttrNVPolicyWrite|tpm2.AttrNVAuthRead|tpm2.AttrNVNoDA|tpm2.AttrNVReadStClear|tpm2.AttrNVWritten {
		t.Errorf("Lock NV index has the wrong attributes")
	}
	if pub.Size != uint16(0) {
		t.Errorf("Lock NV index has the wrong size")
	}

	dataIndex, err := tpm.CreateResourceContextFromTPM(LockNVDataHandle)
	if err != nil {
		t.Fatalf("Cannot create context for lock policy data NV index: %v", err)
	}

	dataPub, _, err := tpm.NVReadPublic(dataIndex)
	if err != nil {
		t.Fatalf("NVReadPublic failed: %v", err)
	}
	data, err := tpm.NVRead(dataIndex, dataIndex, dataPub.Size, 0, nil)
	if err != nil {
		t.Fatalf("NVRead failed: %v", err)
	}

	var version uint8
	var keyName tpm2.Name
	var clock uint64
	if _, err := tpm2.UnmarshalFromBytes(data, &version, &keyName, &clock); err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}

	if version != 0 {
		t.Errorf("Unexpected version for lock NV index policy")
	}

	clockBytes := make([]byte, binary.Size(clock))
	binary.BigEndian.PutUint64(clockBytes, clock)

	trial, _ := tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicyCommandCode(tpm2.CommandNVWrite)
	trial.PolicyCounterTimer(clockBytes, 8, tpm2.OpUnsignedLT)
	trial.PolicySigned(keyName, nil)

	if !bytes.Equal(trial.GetDigest(), pub.AuthPolicy) {
		t.Errorf("Lock NV index has the wrong authorization policy")
	}
}

func TestIncrementDynamicPolicyCounter(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	keyPublic := CreatePublicAreaForRSASigningKey(&key.PublicKey)
	keyName, err := keyPublic.Name()
	if err != nil {
		t.Fatalf("Cannot compute key name: %v", err)
	}

	pinIndexPub, pinIndexAuthPolicies, err := CreatePinNVIndex(tpm.TPMContext, 0x0181ff00, keyName, tpm.HmacSession())
	if err != nil {
		t.Fatalf("CreatePinNVIndex failed: %v", err)
	}
	defer func() {
		index, err := tpm2.CreateNVIndexResourceContextFromPublic(pinIndexPub)
		if err != nil {
			t.Errorf("CreateNVIndexResourceContextFromPublic failed: %v", err)
		}
		undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
	}()

	initialCount, err := ReadDynamicPolicyCounter(tpm.TPMContext, pinIndexPub, pinIndexAuthPolicies, tpm.HmacSession())
	if err != nil {
		t.Errorf("ReadDynamicPolicyCounter failed: %v", err)
	}

	if err := IncrementDynamicPolicyCounter(tpm.TPMContext, pinIndexPub, pinIndexAuthPolicies, key, keyPublic, tpm.HmacSession()); err != nil {
		t.Fatalf("IncrementDynamicPolicyCounter failed: %v", err)
	}

	count, err := ReadDynamicPolicyCounter(tpm.TPMContext, pinIndexPub, pinIndexAuthPolicies, tpm.HmacSession())
	if err != nil {
		t.Errorf("ReadDynamicPolicyCounter failed: %v", err)
	}
	if count != initialCount+1 {
		t.Errorf("ReadDynamicPolicyCounter returned an unexpected count (got %d, expected %d)", count, initialCount+1)
	}
}

func TestReadDynamicPolicyCounter(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	testPublic := tpm2.NVPublic{
		Index:   0x0181fe00,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVAuthRead),
		Size:    8}
	testIndex, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &testPublic, nil)
	if err != nil {
		t.Fatalf("NVDefineSpace failed: %v", err)
	}
	defer undefineNVSpace(t, tpm, testIndex, tpm.OwnerHandleContext())
	if err := tpm.NVIncrement(testIndex, testIndex, nil); err != nil {
		t.Fatalf("NVIncrement failed: %v", err)
	}
	testCount, err := tpm.NVReadCounter(testIndex, testIndex, nil)
	if err != nil {
		t.Fatalf("NVReadCounter failed: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 768)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	keyPublic := CreatePublicAreaForRSASigningKey(&key.PublicKey)
	keyName, err := keyPublic.Name()
	if err != nil {
		t.Fatalf("Cannot compute key name: %v", err)
	}

	pinIndexPub, pinIndexAuthPolicies, err := CreatePinNVIndex(tpm.TPMContext, 0x0181ff00, keyName, tpm.HmacSession())
	if err != nil {
		t.Fatalf("CreatePinNVIndex failed: %v", err)
	}
	defer func() {
		index, err := tpm2.CreateNVIndexResourceContextFromPublic(pinIndexPub)
		if err != nil {
			t.Errorf("CreateNVIndexResourceContextFromPublic failed: %v", err)
		}
		undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
	}()

	count, err := ReadDynamicPolicyCounter(tpm.TPMContext, pinIndexPub, pinIndexAuthPolicies, tpm.HmacSession())
	if err != nil {
		t.Errorf("ReadDynamicPolicyCounter failed: %v", err)
	}
	if count != testCount {
		t.Errorf("ReadDynamicPolicyCounter returned an unexpected count (got %d, expected %d)", count, testCount)
	}
}

func undefineLockNVIndices(t *testing.T, tpm *TPMConnection) {
	if index, err := tpm.CreateResourceContextFromTPM(LockNVHandle); err == nil {
		undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
	}
	if index, err := tpm.CreateResourceContextFromTPM(LockNVDataHandle); err == nil {
		undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
	}
}

func TestEnsureLockNVIndex(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	undefineLockNVIndices(t, tpm)
	if err := EnsureLockNVIndex(tpm.TPMContext, tpm.HmacSession()); err != nil {
		t.Errorf("EnsureLockNVIndex failed: %v", err)
	}
	defer func() {
		index, err := tpm.CreateResourceContextFromTPM(LockNVHandle)
		if err != nil {
			t.Errorf("CreateResourceContextFromTPM failed: %v", err)
		}
		undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
		index, err = tpm.CreateResourceContextFromTPM(LockNVDataHandle)
		if err != nil {
			t.Errorf("CreateResourceContextFromTPM failed: %v", err)
		}
		undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
	}()

	validateLockNVIndex(t, tpm.TPMContext)

	index, err := tpm.CreateResourceContextFromTPM(LockNVHandle)
	if err != nil {
		t.Fatalf("No lock NV index created")
	}
	origName := index.Name()

	if err := EnsureLockNVIndex(tpm.TPMContext, tpm.HmacSession()); err != nil {
		t.Errorf("EnsureLockNVIndex failed: %v", err)
	}

	index, err = tpm.CreateResourceContextFromTPM(LockNVHandle)
	if err != nil {
		t.Fatalf("No lock NV index created")
	}
	if !bytes.Equal(index.Name(), origName) {
		t.Errorf("lock NV index shouldn't have been recreated")
	}
}

func TestReadAndValidateLockNVIndexPublic(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	prepare := func(t *testing.T) (tpm2.ResourceContext, tpm2.ResourceContext) {
		undefineLockNVIndices(t, tpm)
		if err := EnsureLockNVIndex(tpm.TPMContext, tpm.HmacSession()); err != nil {
			t.Errorf("EnsureLockNVIndex failed: %v", err)
		}
		index, err := tpm.CreateResourceContextFromTPM(LockNVHandle)
		if err != nil {
			t.Fatalf("No lock NV index created")
		}
		dataIndex, err := tpm.CreateResourceContextFromTPM(LockNVDataHandle)
		if err != nil {
			t.Fatalf("No lock NV data index created")
		}
		return index, dataIndex
	}

	t.Run("Good", func(t *testing.T) {
		index, dataIndex := prepare(t)
		defer func() {
			undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
			undefineNVSpace(t, tpm, dataIndex, tpm.OwnerHandleContext())
		}()
		pub, err := ReadAndValidateLockNVIndexPublic(tpm.TPMContext, index, tpm.HmacSession())
		if err != nil {
			t.Fatalf("ReadAndValidateLockNVIndexPublic failed: %v", err)
		}
		if pub.Index != LockNVHandle {
			t.Errorf("Returned public area has wrong handle")
		}
		if pub.Attrs != LockNVIndexAttrs|tpm2.AttrNVWritten {
			t.Errorf("incorrect lock NV index attributes")
		}
	})

	t.Run("ReadLocked", func(t *testing.T) {
		index, dataIndex := prepare(t)
		defer func() {
			undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
			undefineNVSpace(t, tpm, dataIndex, tpm.OwnerHandleContext())
		}()
		if err := tpm.NVReadLock(index, index, nil); err != nil {
			t.Fatalf("NVReadLock failed: %v", err)
		}
		pub, err := ReadAndValidateLockNVIndexPublic(tpm.TPMContext, index, tpm.HmacSession())
		if err != nil {
			t.Fatalf("ReadAndValidateLockNVIndexPublic failed: %v", err)
		}
		if pub.Index != LockNVHandle {
			t.Errorf("Returned public area has wrong handle")
		}
		if pub.Attrs != LockNVIndexAttrs|tpm2.AttrNVWritten {
			t.Errorf("incorrect lock NV index attributes")
		}
	})

	t.Run("NoPolicyDataIndex", func(t *testing.T) {
		index, dataIndex := prepare(t)
		defer undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
		if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), dataIndex, nil); err != nil {
			t.Fatalf("NVUndefineSpace failed: %v", err)
		}
		pub, err := ReadAndValidateLockNVIndexPublic(tpm.TPMContext, index, tpm.HmacSession())
		if pub != nil {
			t.Errorf("ReadAndValidateLockNVIndexPublic should have returned no public area")
		}
		var ruErr tpm2.ResourceUnavailableError
		if !xerrors.As(err, &ruErr) {
			t.Errorf("Unexpected error type")
		}
		if ruErr.Handle != LockNVDataHandle {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("IncorrectClockValue", func(t *testing.T) {
		index, dataIndex := prepare(t)
		dataIndexUndefined := false
		defer func() {
			undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())
			if dataIndexUndefined {
				return
			}
			undefineNVSpace(t, tpm, dataIndex, tpm.OwnerHandleContext())
		}()

		// Test with a policy data index that indicates a time in the future.

		dataPub, _, err := tpm.NVReadPublic(dataIndex)
		if err != nil {
			t.Fatalf("NVReadPublic failed: %v", err)
		}
		data, err := tpm.NVRead(dataIndex, dataIndex, dataPub.Size, 0, nil)
		if err != nil {
			t.Fatalf("NVRead failed: %v", err)
		}
		var version uint8
		var keyName tpm2.Name
		var clock uint64
		if _, err := tpm2.UnmarshalFromBytes(data, &version, &keyName, &clock); err != nil {
			t.Fatalf("UnmarshalFromBytes failed: %v", err)
		}

		time, err := tpm.ReadClock()
		if err != nil {
			t.Fatalf("ReadClock failed: %v", err)
		}

		data, err = tpm2.MarshalToBytes(version, keyName, time.ClockInfo.Clock+3600000)
		if err != nil {
			t.Errorf("MarshalToBytes failed: %v", err)
		}

		if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), dataIndex, nil); err != nil {
			t.Fatalf("NVUndefineSpace failed: %v", err)
		}
		dataIndexUndefined = true

		public := tpm2.NVPublic{
			Index:   LockNVDataHandle,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVWriteDefine | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
			Size:    uint16(len(data))}
		dataIndex, err = tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &public, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		defer undefineNVSpace(t, tpm, dataIndex, tpm.OwnerHandleContext())

		if err := tpm.NVWrite(dataIndex, dataIndex, data, 0, nil); err != nil {
			t.Errorf("NVWrite failed: %v", err)
		}
		pub, err := ReadAndValidateLockNVIndexPublic(tpm.TPMContext, index, tpm.HmacSession())
		if err == nil {
			t.Fatalf("ReadAndValidateLockNVIndexPublic should have failed")
		}
		if pub != nil {
			t.Errorf("ReadAndValidateLockNVIndexPublic should have returned no public area")
		}
		if err.Error() != "unexpected clock value in policy data" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("IncorrectPolicy", func(t *testing.T) {
		clearTPMWithPlatformAuth(t, tpm)

		// Test with a bogus lock NV index that allows writes far in to the future, making it possible
		// to recreate it to remove the read lock bit.

		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		keyPublic := CreatePublicAreaForRSASigningKey(&key.PublicKey)
		keyName, err := keyPublic.Name()
		if err != nil {
			t.Errorf("Cannot compute key name: %v", err)
		}

		time, err := tpm.ReadClock()
		if err != nil {
			t.Fatalf("ReadClock failed: %v", err)
		}
		time.ClockInfo.Clock += 5000
		clockBytes := make(tpm2.Operand, binary.Size(time.ClockInfo.Clock))
		binary.BigEndian.PutUint64(clockBytes, time.ClockInfo.Clock+3600000000)

		trial, _ := tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
		trial.PolicyCommandCode(tpm2.CommandNVWrite)
		trial.PolicyCounterTimer(clockBytes, 8, tpm2.OpUnsignedLT)
		trial.PolicySigned(keyName, nil)

		public := tpm2.NVPublic{
			Index:      LockNVHandle,
			NameAlg:    tpm2.HashAlgorithmSHA256,
			Attrs:      LockNVIndexAttrs,
			AuthPolicy: trial.GetDigest(),
			Size:       0}
		index, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &public, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		defer undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext())

		policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer tpm.FlushContext(policySession)

		h := tpm2.HashAlgorithmSHA256.NewHash()
		h.Write(policySession.NonceTPM())
		binary.Write(h, binary.BigEndian, int32(0))

		sig, err := rsa.SignPSS(rand.Reader, key, tpm2.HashAlgorithmSHA256.GetHash(), h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			t.Errorf("SignPSS failed: %v", err)
		}

		keyLoaded, err := tpm.LoadExternal(nil, keyPublic, tpm2.HandleEndorsement)
		if err != nil {
			t.Fatalf("LoadExternal failed: %v", err)
		}
		defer tpm.FlushContext(keyLoaded)

		signature := tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgRSAPSS,
			Signature: tpm2.SignatureU{
				Data: &tpm2.SignatureRSAPSS{
					Hash: tpm2.HashAlgorithmSHA256,
					Sig:  tpm2.PublicKeyRSA(sig)}}}

		if err := tpm.PolicyCommandCode(policySession, tpm2.CommandNVWrite); err != nil {
			t.Errorf("Assertion failed: %v", err)
		}
		if err := tpm.PolicyCounterTimer(policySession, clockBytes, 8, tpm2.OpUnsignedLT); err != nil {
			t.Errorf("Assertion failed: %v", err)
		}
		if _, _, err := tpm.PolicySigned(keyLoaded, policySession, true, nil, nil, 0, &signature); err != nil {
			t.Errorf("Assertion failed: %v", err)
		}

		if err := tpm.NVWrite(index, index, nil, 0, policySession); err != nil {
			t.Errorf("NVWrite failed: %v", err)
		}

		data, err := tpm2.MarshalToBytes(uint8(0), keyName, time.ClockInfo.Clock)
		if err != nil {
			t.Fatalf("MarshalToBytes failed: %v", err)
		}

		// Create the data index.
		dataPublic := tpm2.NVPublic{
			Index:   LockNVDataHandle,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVWriteDefine | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
			Size:    uint16(len(data))}
		dataIndex, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &dataPublic, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		defer undefineNVSpace(t, tpm, dataIndex, tpm.OwnerHandleContext())

		if err := tpm.NVWrite(dataIndex, dataIndex, data, 0, nil); err != nil {
			t.Errorf("NVWrite failed: %v", err)
		}

		pub, err := ReadAndValidateLockNVIndexPublic(tpm.TPMContext, index, tpm.HmacSession())
		if err == nil {
			t.Fatalf("ReadAndValidateLockNVIndexPublic should have failed")
		}
		if pub != nil {
			t.Errorf("ReadAndValidateLockNVIndexPublic should have returned no public area")
		}
		if err.Error() != "incorrect policy for NV index" {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}

func TestComputeStaticPolicy(t *testing.T) {
	block, _ := pem.Decode([]byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvVGKq3nV0WMpEEQBhroTTHjYRZWHjQlSFXkgvUxurXkMlkti
U8LKJqRUI+ekJ5mCQR5JTMnX59HE/jdL1zYzWP6PjKDlpBU5UcY3chWQ9gM2t7+l
VuY/b8fq4We/P6neNBAMOx8Ip8UAuPzCbWSxCqsMq1Mp3iDUcSGM54OEDupATsqj
LTm6elgHz6Ik92Tzy20Z66mYo02M41VenSSndEFA4zORePek2nHOfklRJvokgnX9
ujwuwUAG80EEOrQavBLQFSzmlc9q0N0GeWp23yfl5Cd84RkzNIFgxnLlUH4og5mN
4Ti3YpI57iXvBsOzFIZ+WXYQROEIP3aiJuNOhQIDAQABAoIBAQCMwk7fFdQDPb3v
SRD1ce4dYpAylG3XUAHG02ujM2vq8OCJ8nymGGMi/fVNSNJFWx58eh83x68OvmnA
Na7e0X62AXcLsSlsqRcYFM9utFg2gccyMXymMsUhwDuD4hZRKGR8wx3E61sNGi1i
XRPWMBJuAyWFUG0FqdUqVC6mh6MtTnh2rzPbU6UnT3a6UsGwy6U1FftuexkXY+bb
mfpwA3lR3p1hgqdKF9DC7C4vsSFzBI2M0vVWX0T76GxhVtVle2XLsKrVjqPnUn1D
59vQt1xr/lluHJp/FP9be0wL3bwOTnDdgpBN2APrFcfyJ6kqJuwL6EdFPSsg3C0M
Q73j0kVBAoGBAOP2FMuhsZxhyNDpTZqS6zbdXy2Z3Mjop70tFj2m11gYOYJ10I/J
7fLPhOuFeNA7Kp8S5iH0hTgk+dd9UD8SV/clj14+tdXjLoMDbqWQ4JXurdk/dXML
46eOuRUUxCFFxmR1EwPzaV1nsNOStFd2HG4s4vpPcOVJ7r0RimOjzj9VAoGBANSa
swXqzleRKrGtDRrqUDZXKP43dyVXgQdLRpAIK6W8GdIbcuvYXmBZG1sFYpK7COJR
/xG6CaPPbDHg8VbE7E5WW3tYi7RvycLJoyYW6EhjqVIMYNVFR6BrHugKNa7KSdHK
UwAYKgL6KYtYEU9ZDBEX2HT9Wd9SGXiwvhl/D/JxAoGAG6AIqRyxL2hSM67yLpc7
VezByf7pWJeJLE24ckQzuINHBN5OJf6sjU5Ep14HZASnh5t8tASz2Dfy5wBSpzIL
4vF0TFGBK6haTJov4HSMIt9HxhoAm66HKhkLqNhZZEbWYfomEcZ/sEgOj7UpkafI
jjl2UCssXTz2Z4cmpCiHp/kCgYA8IaUQv2CtE7nnlvJl8m/NbsmBXV6tiRpNXdUP
V8BAl/sVmf3fBstqpMk/7T38EjppCJgEA4JGepw3X0/jIr9TSMmHEXwyBIwkM7OZ
SlFYaBezxRx+NaIUlTegmYKldUF7vKXNGQiI3whxCO+caasoCn6GWEHbD/V0VUjv
HSj9gQKBgDMhQh5RaTBuU8BIEmzS8DVVv6DUi9Wr8vblVPDEDgTEEeRq1B7OIpnk
QZUMW/hqX6qMtjD1lnygOGT3mL9YlSuGyGymsTqWyJM09XbbK9fXm0g3UGv5sOyb
duwzA18V2dm66mFx1NcqfNyRUbclhN26KAaRnTDQrAaxFIgoO+Xm
-----END RSA PRIVATE KEY-----`))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS1PrivateKey failed: %v", err)
	}

	// Generate an authorization policy for the PIN NV index public area below. For the purposes of this test, these digests could really
	// be anything, although the ones here do actually correspond to valid authorization policies - the first one is for initialization
	// with an asymmetric key that has been discarded. The second one is for updating with the above key. The final 3 are valid policies
	// for PIN change (TPM2_NV_ChangeAuth), reading (TPM2_NV_Read) and TPM2_PolicyNV - see the first 5 calls to tpm2.ComputeAuthPolicy in
	// createPinNVIndex.
	var pinIndexAuthPolicies tpm2.DigestList
	pinIndexAuthPolicies = append(pinIndexAuthPolicies, decodeHexString(t, "199c42684aafe3d9c2e18dcc162a6d3875a40ca2ab8f06228b207135281d995f"))
	pinIndexAuthPolicies = append(pinIndexAuthPolicies, decodeHexString(t, "78b1915a25b400ec9a87a2830b07aaacfc440f754e0d2027d09799f894d134c0"))
	pinIndexAuthPolicies = append(pinIndexAuthPolicies, decodeHexString(t, "aa83a598d93a56c9ca6fea7c3ffc4e106357ff6d93e11a9b4ac2b6aae12ba0de"))
	pinIndexAuthPolicies = append(pinIndexAuthPolicies, decodeHexString(t, "47ce3032d8bad1f3089cb0c09088de43501491d460402b90cd1b7fc0b68ca92f"))
	pinIndexAuthPolicies = append(pinIndexAuthPolicies, decodeHexString(t, "203e4bd5d0448c9615cc13fa18e8d39222441cc40204d99a77262068dbd55a43"))

	trial, _ := tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicyOR(pinIndexAuthPolicies)

	pinIndexPub := &tpm2.NVPublic{
		Index:      0x0181fff0,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVPolicyRead | tpm2.AttrNVWritten),
		AuthPolicy: trial.GetDigest(),
		Size:       8}

	lockIndexPub := tpm2.NVPublic{
		Index:      LockNVHandle,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA | tpm2.AttrNVReadStClear | tpm2.AttrNVWritten),
		AuthPolicy: make(tpm2.Digest, tpm2.HashAlgorithmSHA256.Size()),
		Size:       0}
	lockName, _ := lockIndexPub.Name()

	for _, data := range []struct {
		desc   string
		alg    tpm2.HashAlgorithmId
		policy tpm2.Digest
	}{
		{
			desc:   "SHA256",
			alg:    tpm2.HashAlgorithmSHA256,
			policy: decodeHexString(t, "6996f631d4ff9ebe51aaf91f155446ea3b845f9d7f3c33d70efc3b44cbf9fde4"),
		},
		{
			desc:   "SHA1",
			alg:    tpm2.HashAlgorithmSHA1,
			policy: decodeHexString(t, "97859d33468dd99d02449128b5c0cda40fc2c272"),
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			dataout, policy, err := ComputeStaticPolicy(data.alg, NewStaticPolicyComputeParams(&key.PublicKey, pinIndexPub, pinIndexAuthPolicies, lockName))
			if err != nil {
				t.Fatalf("ComputeStaticPolicy failed: %v", err)
			}
			if dataout.AuthPublicKey.Params.RSADetail().Exponent != uint32(key.PublicKey.E) {
				t.Errorf("Auth key public area has wrong exponent")
			}
			if dataout.AuthPublicKey.Params.RSADetail().KeyBits != uint16(key.PublicKey.N.BitLen()) {
				t.Errorf("Auth key public area has wrong bit length")
			}
			if !bytes.Equal(dataout.AuthPublicKey.Unique.RSA(), key.PublicKey.N.Bytes()) {
				t.Errorf("Auth key public area has wrong modulus")
			}
			if dataout.PinIndexHandle != pinIndexPub.Index {
				t.Errorf("Wrong PIN NV index handle")
			}
			if len(dataout.PinIndexAuthPolicies) != len(pinIndexAuthPolicies) {
				t.Fatalf("Wrong number of PIN NV index auth policies")
			}
			for i, d := range dataout.PinIndexAuthPolicies {
				if !bytes.Equal(d, pinIndexAuthPolicies[i]) {
					t.Errorf("Wrong PIN NV index auth policy")
				}
			}
			if !bytes.Equal(policy, data.policy) {
				t.Errorf("Wrong policy digest: %x", policy)
			}
		})
	}
}

func makePCRDigestFromEvents(alg tpm2.HashAlgorithmId, events ...string) tpm2.Digest {
	p := make(tpm2.Digest, alg.Size())
	for _, e := range events {
		h := alg.NewHash()
		h.Write([]byte(e))
		d := h.Sum(nil)

		h = alg.NewHash()
		h.Write(p)
		h.Write(d)
		p = h.Sum(nil)
	}
	return p
}

type pcrDigestBuilder struct {
	t           *testing.T
	alg         tpm2.HashAlgorithmId
	pcrs        tpm2.PCRSelectionList
	pcrsCurrent tpm2.PCRSelectionList
	values      tpm2.PCRValues
}

func (b *pcrDigestBuilder) addDigest(digest tpm2.Digest) *pcrDigestBuilder {
	for {
		if len(b.pcrsCurrent) == 0 {
			b.t.Fatalf("No more digests required")
		}
		if len(b.pcrsCurrent[0].Select) > 0 {
			break
		}
		b.pcrsCurrent = b.pcrsCurrent[1:]
	}

	b.values.SetValue(b.pcrsCurrent[0].Select[0], b.pcrsCurrent[0].Hash, digest)

	b.pcrsCurrent[0].Select = b.pcrsCurrent[0].Select[1:]
	return b
}

func (b *pcrDigestBuilder) end() tpm2.Digest {
	digest, err := tpm2.ComputePCRDigest(b.alg, b.pcrs, b.values)
	if err != nil {
		b.t.Fatalf("ComputePCRDigest failed: %v", err)
	}
	return digest
}

func buildPCRDigest(t *testing.T, alg tpm2.HashAlgorithmId, pcrs tpm2.PCRSelectionList) *pcrDigestBuilder {
	var pcrs2 tpm2.PCRSelectionList
	for _, p := range pcrs {
		p2 := tpm2.PCRSelection{Hash: p.Hash}
		p2.Select = make([]int, len(p.Select))
		copy(p2.Select, p.Select)
		sort.Ints(p2.Select)
		pcrs2 = append(pcrs2, p2)
	}
	return &pcrDigestBuilder{t: t, alg: alg, pcrs: pcrs, pcrsCurrent: pcrs2, values: make(tpm2.PCRValues)}
}

func TestComputeDynamicPolicy(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	pinIndexPub := &tpm2.NVPublic{
		Index:      0x0181fff0,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVPolicyRead | tpm2.AttrNVWritten),
		AuthPolicy: make(tpm2.Digest, tpm2.HashAlgorithmSHA256.Size()),
		Size:       8}
	pinName, _ := pinIndexPub.Name()

	for _, data := range []struct {
		desc         string
		alg          tpm2.HashAlgorithmId
		signAlg      tpm2.HashAlgorithmId
		pcrParams    []MockPolicyPCRParam
		policyCount  uint64
		pcrSelection tpm2.PCRSelectionList
		pcrOrDigests tpm2.DigestList
		policy       tpm2.Digest
	}{
		{
			desc:    "Single/1",
			alg:     tpm2.HashAlgorithmSHA256,
			signAlg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar")}}},
			policyCount:  10,
			pcrSelection: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			policy:       decodeHexString(t, "3cbe37896850d15904508ddf7a28f776642fe60e10b8c9b35e22f50bdc3a53dc"),
		},
		{
			desc:    "Single/2",
			alg:     tpm2.HashAlgorithmSHA256,
			signAlg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo")}},
				MockPolicyPCRParam{PCR: 8, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar")}}},
			policyCount:  10,
			pcrSelection: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 8}}},
			policy:       decodeHexString(t, "86affbdd808f57ef16c369fc2cc099a3bfa4de6d39a5c4a2cba83710c555ecbe"),
		},
		{
			desc:    "SHA1Session",
			alg:     tpm2.HashAlgorithmSHA1,
			signAlg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "ABC")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "1234")}}},
			policyCount:  4551,
			pcrSelection: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			policy:       decodeHexString(t, "28ac61ddced6e86df127edebeea647b9dc5ca84d"),
		},
		{
			desc:    "SHA256SessionWithSHA512PCRs",
			alg:     tpm2.HashAlgorithmSHA256,
			signAlg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA512, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA512, "foo")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA512, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA512, "bar")}}},
			policyCount:  403,
			pcrSelection: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA512, Select: []int{7, 12}}},
			policy:       decodeHexString(t, "3600c82daa5035cd43270f3bc3d0e54beb5c822068ba1951e1bb8757f9dd1d15"),
		},
		{
			desc:    "MultiplePCRValues",
			alg:     tpm2.HashAlgorithmSHA256,
			signAlg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{
					makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{
					makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "ABC"),
					makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "1234")}}},
			policyCount:  5,
			pcrSelection: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			policy:       decodeHexString(t, "a17b393df59e27da3052bce83dbd8d97e777c4967c2ffa9ea9cc096a65944eed"),
		},
		{
			desc:    "SHA512AuthKey",
			alg:     tpm2.HashAlgorithmSHA256,
			signAlg: tpm2.HashAlgorithmSHA512,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar")}}},
			policyCount:  10,
			pcrSelection: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 12}}},
			policy:       decodeHexString(t, "3cbe37896850d15904508ddf7a28f776642fe60e10b8c9b35e22f50bdc3a53dc"),
		},
		{
			desc:    "MultiplePCRAlgorithms",
			alg:     tpm2.HashAlgorithmSHA256,
			signAlg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA512, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo")}},
				MockPolicyPCRParam{PCR: 8, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar")}}},
			policyCount:  10,
			pcrSelection: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA512, Select: []int{7}}, {Hash: tpm2.HashAlgorithmSHA256, Select: []int{8}}},
			policy:       decodeHexString(t, "1744562fbc67243d2a85fc293d9ccba1381ee835890044b23af957d0be44486e"),
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			dataout, err := ComputeDynamicPolicy(data.alg, NewDynamicPolicyComputeParams(key, data.signAlg, data.pcrParams, pinName, data.policyCount))
			if err != nil {
				t.Fatalf("ComputeDynamicPolicy failed; %v", err)
			}
			if len(dataout.PCRSelection) != len(data.pcrSelection) {
				t.Errorf("Unexpected PCR selection length")
			} else {
				for i := range dataout.PCRSelection {
					if dataout.PCRSelection[i].Hash != data.pcrSelection[i].Hash {
						t.Errorf("Unexpected algorithm for PCR selection")
					}
					if len(dataout.PCRSelection[i].Select) != len(data.pcrSelection[i].Select) {
						t.Errorf("Unexpected number of PCRs in selection")
					} else {
						for j := range dataout.PCRSelection[i].Select {
							if dataout.PCRSelection[i].Select[j] != data.pcrSelection[i].Select[j] {
								t.Errorf("Unexpected PCR in selection")
							}
						}
					}
				}
			}
			numPcrOrDigests := 0
			for _, p := range data.pcrParams {
				if numPcrOrDigests == 0 {
					numPcrOrDigests = 1
				}
				numPcrOrDigests *= len(p.Digests)
			}
			//if len(dataout.PCROrDigests) != numPcrOrDigests {
			//	t.Errorf("Unexpected number of PCR OR digests")
			//}
			//for _, d := range dataout.PCROrDigests {
			//	if len(d) != data.alg.Size() {
			//		t.Errorf("Unexpected OR digest size")
			//	}
			//}

			if dataout.PolicyCount != data.policyCount {
				t.Errorf("Unexpected policy revocation count")
			}

			if !bytes.Equal(data.policy, dataout.AuthorizedPolicy) {
				t.Errorf("Unexpected policy digest returned (got %x, expected %x)", dataout.AuthorizedPolicy, data.policy)
			}

			if dataout.AuthorizedPolicySignature.SigAlg != tpm2.SigSchemeAlgRSAPSS {
				t.Errorf("Unexpected authorized policy signature algorithm")
			}
			if dataout.AuthorizedPolicySignature.Signature.RSAPSS().Hash != data.signAlg {
				t.Errorf("Unexpected authorized policy signature digest algorithm")
			}

			h := data.signAlg.NewHash()
			h.Write(dataout.AuthorizedPolicy)

			if err := rsa.VerifyPSS(&key.PublicKey, data.signAlg.GetHash(), h.Sum(nil),
				[]byte(dataout.AuthorizedPolicySignature.Signature.RSAPSS().Sig),
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
				t.Errorf("Invalid authorized policy signature: %v", err)
			}
		})
	}
}

func TestExecutePolicy(t *testing.T) {
	tpm, tcti := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	undefineLockNVIndices(t, tpm)
	if err := EnsureLockNVIndex(tpm.TPMContext, tpm.HmacSession()); err != nil {
		t.Errorf("ensureLockNVIndex failed: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	keyPublic := CreatePublicAreaForRSASigningKey(&key.PublicKey)
	keyName, err := keyPublic.Name()
	if err != nil {
		t.Fatalf("Cannot compute key name: %v", err)
	}

	pinIndexPub, pinIndexAuthPolicies, err := CreatePinNVIndex(tpm.TPMContext, 0x0181ff00, keyName, tpm.HmacSession())
	if err != nil {
		t.Fatalf("CreatePinNVIndex failed: %v", err)
	}
	pinIndex, err := tpm2.CreateNVIndexResourceContextFromPublic(pinIndexPub)
	if err != nil {
		t.Fatalf("CreateNVIndexResourceContextFromPublic failed: %v", err)
	}
	defer undefineNVSpace(t, tpm, pinIndex, tpm.OwnerHandleContext())

	policyCount, err := ReadDynamicPolicyCounter(tpm.TPMContext, pinIndexPub, pinIndexAuthPolicies, tpm.HmacSession())
	if err != nil {
		t.Fatalf("readDynamicPolicyCounter failed: %v", err)
	}

	type pcrEvent struct {
		index int
		data  string
	}
	type testData struct {
		alg         tpm2.HashAlgorithmId
		pcrParams   []MockPolicyPCRParam
		policyCount uint64
		pcrEvents   []pcrEvent
		pinDefine   string
		pinInput    string
	}

	run := func(t *testing.T, data *testData, prepare func(*StaticPolicyData, *DynamicPolicyData)) (tpm2.Digest, tpm2.Digest, error) {
		resetTPMSimulator(t, tpm, tcti)

		lockIndex, err := tpm.CreateResourceContextFromTPM(LockNVHandle)
		if err != nil {
			t.Fatalf("CreateResourceContextFromTPM failed: %v", err)
		}

		var pinIndexAuthPoliciesCopy tpm2.DigestList
		for _, d := range pinIndexAuthPolicies {
			c := make(tpm2.Digest, len(d))
			copy(c, d)
			pinIndexAuthPoliciesCopy = append(pinIndexAuthPoliciesCopy, c)
		}

		staticPolicyData, policy, err := ComputeStaticPolicy(data.alg, NewStaticPolicyComputeParams(&key.PublicKey, pinIndexPub, pinIndexAuthPoliciesCopy, lockIndex.Name()))
		if err != nil {
			t.Fatalf("ComputeStaticPolicy failed: %v", err)
		}
		signAlg := staticPolicyData.AuthPublicKey.NameAlg
		dynamicPolicyData, err := ComputeDynamicPolicy(data.alg, NewDynamicPolicyComputeParams(key, signAlg, data.pcrParams, pinIndex.Name(), data.policyCount))
		if err != nil {
			t.Fatalf("ComputeDynamicPolicy failed: %v", err)
		}

		for _, e := range data.pcrEvents {
			if _, err := tpm.PCREvent(tpm.PCRHandleContext(e.index), []byte(e.data), nil); err != nil {
				t.Fatalf("PCREvent failed: %v", err)
			}
		}

		if data.pinDefine != "" {
			if err := PerformPinChange(tpm.TPMContext, pinIndexPub, pinIndexAuthPolicies, "", data.pinDefine, tpm.HmacSession()); err != nil {
				t.Fatalf("PerformPinChange failed: %v", err)
			}
			defer func() {
				if err := PerformPinChange(tpm.TPMContext, pinIndexPub, pinIndexAuthPolicies, data.pinDefine, "", tpm.HmacSession()); err != nil {
					t.Errorf("Resetting PIN failed: %v", err)
				}
			}()
		}

		if prepare != nil {
			prepare((*StaticPolicyData)(staticPolicyData), (*DynamicPolicyData)(dynamicPolicyData))
		}

		session, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, data.alg)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, session)

		policyErr := ExecutePolicySession(tpm.TPMContext, session, staticPolicyData, dynamicPolicyData, data.pinInput, tpm.HmacSession())
		digest, err := tpm.PolicyGetDigest(session)
		if err != nil {
			t.Errorf("PolicyGetDigest failed: %v", err)
		}

		return policy, digest, policyErr
	}

	t.Run("Single/1", func(t *testing.T) {
		// Test with a policy that includes a single digest for 2 PCRs
		expected, digest, err := run(t, &testData{
			alg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo")}}},
			policyCount: policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, nil)
		if err != nil {
			t.Errorf("Failed to execute policy session: %v", err)
		}
		if !bytes.Equal(digest, expected) {
			t.Errorf("Session digest didn't match policy digest")
		}
	})

	t.Run("Single/2", func(t *testing.T) {
		// Test with a policy that includes a single digest for 2 PCRs
		expected, digest, err := run(t, &testData{
			alg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar")}},
				MockPolicyPCRParam{PCR: 8, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo")}}},
			policyCount: policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 8,
					data:  "bar",
				},
				{
					index: 8,
					data:  "foo",
				},
			}}, nil)
		if err != nil {
			t.Errorf("Failed to execute policy session: %v", err)
		}
		if !bytes.Equal(digest, expected) {
			t.Errorf("Session digest didn't match policy digest")
		}
	})

	t.Run("SHA1SessionWithSHA256PCRs", func(t *testing.T) {
		// Test with a policy that includes a single digest for 2 PCRs and where those PCRs are for an algorithm that doesn't match the
		// policy digest algorithm
		expected, digest, err := run(t, &testData{
			alg: tpm2.HashAlgorithmSHA1,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo")}}},
			policyCount: policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, nil)
		if err != nil {
			t.Errorf("Failed to execute policy session: %v", err)
		}
		if !bytes.Equal(digest, expected) {
			t.Errorf("Session digest didn't match policy digest")
		}
	})

	t.Run("SHA1", func(t *testing.T) {
		// Test with a policy that includes a single digest for 2 PCRs, using the SHA-1 algorithm
		expected, digest, err := run(t, &testData{
			alg: tpm2.HashAlgorithmSHA1,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA1, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA1, "foo", "bar")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA1, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA1, "bar", "foo")}}},
			policyCount: policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, nil)
		if err != nil {
			t.Errorf("Failed to execute policy session: %v", err)
		}
		if !bytes.Equal(digest, expected) {
			t.Errorf("Session digest didn't match policy digest")
		}
	})

	t.Run("WithPIN", func(t *testing.T) {
		// Test with a policy that includes a single digest for 2 PCRs, and uses a PIN
		expected, digest, err := run(t, &testData{
			alg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo")}}},
			policyCount: policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			},
			pinDefine: "1234",
			pinInput:  "1234"}, nil)
		if err != nil {
			t.Errorf("Failed to execute policy session: %v", err)
		}
		if !bytes.Equal(digest, expected) {
			t.Errorf("Session digest didn't match policy digest")
		}
	})

	t.Run("WithIncorrectPIN", func(t *testing.T) {
		// Test with a policy that includes a single digest for 2 PCRs and uses a PIN, with the incorrect PIN provided during execution
		// (execution should fail)
		expected, digest, err := run(t, &testData{
			alg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo")}}},
			policyCount: policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			},
			pinDefine: "1234",
			pinInput:  "12345"}, nil)
		var e *tpm2.TPMSessionError
		if !xerrors.As(err, &e) || e.Code() != tpm2.ErrorAuthFail || e.Command() != tpm2.CommandPolicySecret {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("PCRMismatch/1", func(t *testing.T) {
		// Test with a policy that includes a single digest for 2 PCRs, where the PCR values during execution don't match the policy
		// (execution should fail)
		expected, digest, err := run(t, &testData{
			alg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo")}}},
			policyCount: policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "abc",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, nil)
		if err == nil {
			t.Fatalf("Expected an error")
		}
		if err.Error() != "cannot complete PCR assertions: TPM returned an error for parameter 1 whilst executing command TPM_CC_PolicyOR: TPM_RC_VALUE (value is out of range or is not correct for the context)" {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("PCRMismatch/2", func(t *testing.T) {
		// Test with a policy that includes a single digest for 2 PCRs, where the PCR values during execution don't match the policy
		// (execution should fail)
		expected, digest, err := run(t, &testData{
			alg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo")}}},
			policyCount: policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "xxx",
				},
			}}, nil)
		if err == nil {
			t.Fatalf("Expected an error")
		}
		if err.Error() != "cannot complete PCR assertions: TPM returned an error for parameter 1 whilst executing command TPM_CC_PolicyOR: TPM_RC_VALUE (value is out of range or is not correct for the context)" {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("MultiplePCRValues/1", func(t *testing.T) {
		// Test with a compound policy that includes a pair of digests for 2 PCRs
		expected, digest, err := run(t, &testData{
			alg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{
					makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "baz")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{
					makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "abc", "foo")}}},
			policyCount: policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "abc",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, nil)
		if err != nil {
			t.Errorf("Failed to execute policy session: %v", err)
		}
		if !bytes.Equal(digest, expected) {
			t.Errorf("Session digest didn't match policy digest")
		}
	})

	t.Run("MultiplePCRValues/2", func(t *testing.T) {
		// Test with a compound policy that includes a pair of digests for 2 PCRs
		expected, digest, err := run(t, &testData{
			alg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{
					makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "baz")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{
					makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "abc", "foo")}}},
			policyCount: policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "baz",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, nil)
		if err != nil {
			t.Errorf("Failed to execute policy session: %v", err)
		}
		if !bytes.Equal(digest, expected) {
			t.Errorf("Session digest didn't match policy digest")
		}
	})

	t.Run("MultiplePCRValues/Mismatch", func(t *testing.T) {
		// Test with a compound policy that includes a pair of digests for 2 PCRs, where the PCR values during execution don't match the
		// policy (execution should fail)
		expected, digest, err := run(t, &testData{
			alg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{
					makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "baz")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{
					makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
					makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "abc", "foo")}}},
			policyCount: policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "baz",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "xxx",
				},
			}}, nil)
		if err == nil {
			t.Fatalf("Expected an error")
		}
		if err.Error() != "cannot complete PCR assertions: TPM returned an error for parameter 1 whilst executing command TPM_CC_PolicyOR: TPM_RC_VALUE (value is out of range or is not correct for the context)" {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("NoPCRs", func(t *testing.T) {
		// Test with a policy that includes no PCR assertions - probably fairly pointless, but should work nonetheless
		expected, digest, err := run(t, &testData{
			alg:         tpm2.HashAlgorithmSHA256,
			policyCount: policyCount,
		}, nil)
		if err != nil {
			t.Errorf("Failed to execute policy session: %v", err)
		}
		if !bytes.Equal(digest, expected) {
			t.Errorf("Session digest didn't match policy digest")
		}
	})

	t.Run("RevokedDynamicPolicy", func(t *testing.T) {
		// Test with a dynamic authorization policy that has been revoked (execution should fail)
		expected, digest, err := run(t, &testData{
			alg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo")}}},
			policyCount: policyCount - 1,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, nil)
		var e *tpm2.TPMError
		if !xerrors.As(err, &e) || e.Code != tpm2.ErrorPolicy || e.Command != tpm2.CommandPolicyNV {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("Locked", func(t *testing.T) {
		// Test execution when access to sealed key objects has been locked (execution should fail)
		expected, digest, err := run(t, &testData{
			alg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo")}}},
			policyCount: policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, func(*StaticPolicyData, *DynamicPolicyData) {
			lockIndex, err := tpm.CreateResourceContextFromTPM(LockNVHandle)
			if err != nil {
				t.Fatalf("CreateResourceContextFromTPM failed: %v", err)
			}
			if err := tpm.NVReadLock(lockIndex, lockIndex, nil); err != nil {
				t.Fatalf("NVReadLock failed: %v", err)
			}
		})
		var e *tpm2.TPMError
		if !xerrors.As(err, &e) || e.Code != tpm2.ErrorNVLocked || e.Command != tpm2.CommandPolicyNV {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("InvalidStaticMetadata/PINHandle/1", func(t *testing.T) {
		// Test handling of an invalid handle for the PIN NV index in the static metadata (execution should fail)
		expected, digest, err := run(t, &testData{
			alg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo")}}},
			policyCount: policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, func(s *StaticPolicyData, d *DynamicPolicyData) {
			s.PinIndexHandle = tpm2.Handle(0x40ffffff)
		})
		if err == nil {
			t.Fatalf("Expected an error")
		}
		if err.Error() != "invalid handle type for PIN NV index" {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("InvalidStaticMetadata/PINHandle/2", func(t *testing.T) {
		// Test handling of the PIN NV index in the static metadata pointing to a non-existant resource (execution should fail)
		expected, digest, err := run(t, &testData{
			alg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo")}}},
			policyCount: policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, func(s *StaticPolicyData, d *DynamicPolicyData) {
			s.PinIndexHandle += 1
		})
		var e tpm2.ResourceUnavailableError
		if !xerrors.As(err, &e) {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("InvalidStaticMetadata/PINIndexAuthPolicies/1", func(t *testing.T) {
		// Test handling of invalid PIN NV index auth policy data in the static metadata, where the broken data corresponds to
		// the policy for executing TPM2_PolicyNV (execution should fail)
		expected, digest, err := run(t, &testData{
			alg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo")}}},
			policyCount: policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, func(s *StaticPolicyData, d *DynamicPolicyData) {
			s.PinIndexAuthPolicies[len(s.PinIndexAuthPolicies)-1] = make(tpm2.Digest, len(s.PinIndexAuthPolicies[0]))
		})
		var e *tpm2.TPMParameterError
		if !xerrors.As(err, &e) || e.Code() != tpm2.ErrorValue || e.Command() != tpm2.CommandPolicyOR {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("InvalidStaticMetadata/PINIndexAuthPolicies/2", func(t *testing.T) {
		// Test handling of invalid PIN NV index auth policy data in the static metadata, where the broken data doesn't correspond to
		// the policy for executing TPM2_PolicyNV (execution should fail)
		expected, digest, err := run(t, &testData{
			alg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo")}}},
			policyCount: policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, func(s *StaticPolicyData, d *DynamicPolicyData) {
			s.PinIndexAuthPolicies[0] = make(tpm2.Digest, len(s.PinIndexAuthPolicies[0]))
		})
		var e *tpm2.TPMSessionError
		if !xerrors.As(err, &e) || e.Code() != tpm2.ErrorPolicyFail || e.Command() != tpm2.CommandPolicyNV {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("InvalidStaticMetadata/AuthPublicKey/1", func(t *testing.T) {
		// Test handling of the public area of the dynamic policy authorization key having an unsupported name algorithm (execution should
		// fail)
		expected, digest, err := run(t, &testData{
			alg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo")}}},
			policyCount: policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, func(s *StaticPolicyData, d *DynamicPolicyData) {
			s.AuthPublicKey.NameAlg = tpm2.HashAlgorithmId(tpm2.AlgorithmSM4)
		})
		if err == nil {
			t.Fatalf("Expected an error")
		}
		if err.Error() != "public area of dynamic authorization policy signature verification key has an unsupported name algorithm" {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("InvalidStaticMetadata/AuthPublicKey/2", func(t *testing.T) {
		// Test handling of the public area of the dynamic policy authorization key being replaced by one corresponding to a different key
		// (execution should fail)
		expected, digest, err := run(t, &testData{
			alg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo")}}},
			policyCount: policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, func(s *StaticPolicyData, d *DynamicPolicyData) {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}
			s.AuthPublicKey.Params.RSADetail().KeyBits = uint16(key.N.BitLen())
			s.AuthPublicKey.Params.RSADetail().Exponent = uint32(key.E)
			s.AuthPublicKey.Unique.Data = tpm2.PublicKeyRSA(key.N.Bytes())
		})
		var e *tpm2.TPMParameterError
		if !xerrors.As(err, &e) || e.Code() != tpm2.ErrorSignature || e.Command() != tpm2.CommandVerifySignature || e.Index != 2 {
			t.Errorf("Unexpected error: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("InvalidMetadata/DynamicPolicySignature", func(t *testing.T) {
		// Test handling of the public area of the dynamic policy authorization key being replaced by one corresponding to a different key,
		// and the authorized policy signature being replaced with a signature signed by the new key (execution should succeed, but the
		// resulting session digest shouldn't match the computed policy digest)
		expected, digest, err := run(t, &testData{
			alg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo")}}},
			policyCount: policyCount,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, func(s *StaticPolicyData, d *DynamicPolicyData) {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}
			s.AuthPublicKey.Params.RSADetail().KeyBits = uint16(key.N.BitLen())
			s.AuthPublicKey.Params.RSADetail().Exponent = uint32(key.E)
			s.AuthPublicKey.Unique.Data = tpm2.PublicKeyRSA(key.N.Bytes())

			signAlg := d.AuthorizedPolicySignature.Signature.RSAPSS().Hash
			h := signAlg.NewHash()
			h.Write(d.AuthorizedPolicy)

			sig, err := rsa.SignPSS(rand.Reader, key, signAlg.GetHash(), h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			if err != nil {
				t.Fatalf("SignPSS failed: %v", err)
			}
			d.AuthorizedPolicySignature.Signature.RSAPSS().Sig = tpm2.PublicKeyRSA(sig)
		})
		if err != nil {
			t.Errorf("Failed to execute policy session: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})

	t.Run("InvalidDynamicMetadata/PolicyCount", func(t *testing.T) {
		// Test handling of the policy count in a revoked dynamic policy metadata being changed so that it is equal to the current policy
		// counter value (execution should fail)
		expected, digest, err := run(t, &testData{
			alg: tpm2.HashAlgorithmSHA256,
			pcrParams: []MockPolicyPCRParam{
				MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar")}},
				MockPolicyPCRParam{PCR: 12, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo")}}},
			policyCount: policyCount - 1,
			pcrEvents: []pcrEvent{
				{
					index: 7,
					data:  "foo",
				},
				{
					index: 7,
					data:  "bar",
				},
				{
					index: 12,
					data:  "bar",
				},
				{
					index: 12,
					data:  "foo",
				},
			}}, func(s *StaticPolicyData, d *DynamicPolicyData) {
			d.PolicyCount += 1
		})
		var e *tpm2.TPMParameterError
		if !xerrors.As(err, &e) || e.Code() != tpm2.ErrorValue || e.Command() != tpm2.CommandPolicyAuthorize || e.Index != 1 {
			t.Errorf("Failed to execute policy session: %v", err)
		}
		if bytes.Equal(digest, expected) {
			t.Errorf("Session digest shouldn't match policy digest")
		}
	})
}

func TestLockAccessToSealedKeysUntilTPMReset(t *testing.T) {
	tpm, tcti := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	undefineLockNVIndices(t, tpm)
	if err := EnsureLockNVIndex(tpm.TPMContext, tpm.HmacSession()); err != nil {
		t.Errorf("EnsureLockNVIndex failed: %v", err)
	}

	lockIndex, err := tpm.CreateResourceContextFromTPM(LockNVHandle)
	if err != nil {
		t.Fatalf("CreateResourceContextFromTPM failed: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	keyPublic := CreatePublicAreaForRSASigningKey(&key.PublicKey)
	keyName, err := keyPublic.Name()
	if err != nil {
		t.Fatalf("Cannot compute key name: %v", err)
	}

	pinIndexPub, pinIndexAuthPolicies, err := CreatePinNVIndex(tpm.TPMContext, 0x0181ff00, keyName, tpm.HmacSession())
	if err != nil {
		t.Fatalf("CreatePinNVIndex failed: %v", err)
	}
	pinIndex, err := tpm2.CreateNVIndexResourceContextFromPublic(pinIndexPub)
	if err != nil {
		t.Fatalf("CreateNVIndexResourceContextFromPublic failed: %v", err)
	}
	defer undefineNVSpace(t, tpm, pinIndex, tpm.OwnerHandleContext())

	staticPolicyData, policy, err := ComputeStaticPolicy(tpm2.HashAlgorithmSHA256, NewStaticPolicyComputeParams(&key.PublicKey, pinIndexPub, pinIndexAuthPolicies, lockIndex.Name()))
	if err != nil {
		t.Fatalf("ComputeStaticPolicy failed: %v", err)
	}

	policyCount, err := ReadDynamicPolicyCounter(tpm.TPMContext, pinIndexPub, pinIndexAuthPolicies, tpm.HmacSession())
	if err != nil {
		t.Fatalf("readDynamicPolicyCounter failed: %v", err)
	}

	signAlg := staticPolicyData.AuthPublicKey.NameAlg
	dynamicPolicyData, err := ComputeDynamicPolicy(tpm2.HashAlgorithmSHA256,
		NewDynamicPolicyComputeParams(key, signAlg,
			[]MockPolicyPCRParam{MockPolicyPCRParam{PCR: 7, Alg: tpm2.HashAlgorithmSHA256, Digests: tpm2.DigestList{makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo")}}},
			pinIndex.Name(), policyCount))
	if err != nil {
		t.Fatalf("ComputeDynamicPolicy failed: %v", err)
	}

	for i := 0; i < 2; i++ {
		func() {
			resetTPMSimulator(t, tpm, tcti)

			if _, err := tpm.PCREvent(tpm.PCRHandleContext(7), []byte("foo"), nil); err != nil {
				t.Fatalf("PCREvent failed: %v", err)
			}

			policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, policySession)

			err = ExecutePolicySession(tpm.TPMContext, policySession, staticPolicyData, dynamicPolicyData, "", tpm.HmacSession())
			if err != nil {
				t.Errorf("ExecutePolicySession failed: %v", err)
			}

			digest, err := tpm.PolicyGetDigest(policySession)
			if err != nil {
				t.Errorf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(digest, policy) {
				t.Errorf("Unexpected digests")
			}

			if err := LockAccessToSealedKeysUntilTPMReset(tpm.TPMContext, tpm.HmacSession()); err != nil {
				t.Errorf("LockAccessToSealedKeysUntilTPMReset failed: %v", err)
			}

			if err := tpm.PolicyRestart(policySession); err != nil {
				t.Errorf("PolicyRestart failed: %v", err)
			}

			err = ExecutePolicySession(tpm.TPMContext, policySession, staticPolicyData, dynamicPolicyData, "", tpm.HmacSession())
			var e *tpm2.TPMError
			if !xerrors.As(err, &e) || e.Code != tpm2.ErrorNVLocked || e.Command != tpm2.CommandPolicyNV {
				t.Errorf("Unexpected error: %v", err)
			}

			digest, err = tpm.PolicyGetDigest(policySession)
			if err != nil {
				t.Errorf("PolicyGetDigest failed: %v", err)
			}

			if bytes.Equal(digest, policy) {
				t.Errorf("Unexpected digests")
			}
		}()
	}
}
