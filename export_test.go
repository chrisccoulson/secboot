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
	"crypto/ecdsa"
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/chrisccoulson/tcglog-parser"
)

// Export constants for testing
const (
	CurrentMetadataVersion                = currentMetadataVersion
	LockNVDataHandle                      = lockNVDataHandle
	LockNVHandle                          = lockNVHandle
	SigDbUpdateQuirkModeNone              = sigDbUpdateQuirkModeNone
	SigDbUpdateQuirkModeDedupIgnoresOwner = sigDbUpdateQuirkModeDedupIgnoresOwner
)

// Export variables and unexported functions for testing
var (
	ComputeDbUpdate                          = computeDbUpdate
	ComputePcrPolicy                         = computePcrPolicy
	CreatePcrPolicyCounter                   = createPcrPolicyCounter
	ComputePcrPolicyCounterAuthPolicies      = computePcrPolicyCounterAuthPolicies
	ComputePcrPolicyRefFromCounterContext    = computePcrPolicyRefFromCounterContext
	ComputePcrPolicyRefFromCounterName       = computePcrPolicyRefFromCounterName
	ComputePeImageDigest                     = computePeImageDigest
	ComputePolicyORData                      = computePolicyORData
	ComputeSnapModelDigest                   = computeSnapModelDigest
	ComputeStaticPolicy                      = computeStaticPolicy
	CreateTPMPublicAreaForECDSAKey           = createTPMPublicAreaForECDSAKey
	DecodeSecureBootDb                       = decodeSecureBootDb
	DecodeWinCertificate                     = decodeWinCertificate
	EFICertTypePkcs7Guid                     = efiCertTypePkcs7Guid
	EFICertX509Guid                          = efiCertX509Guid
	EnsureLockNVIndex                        = ensureLockNVIndex
	IdentifyInitialOSLaunchVerificationEvent = identifyInitialOSLaunchVerificationEvent
	IncrementPcrPolicyCounter                = incrementPcrPolicyCounter
	IsKeyDataError                           = isKeyDataError
	IsPolicyDataError                        = isPolicyDataError
	LockNVIndexAttrs                         = lockNVIndexAttrs
	PerformPinChange                         = performPinChange
	ReadAndValidateLockNVIndexPublic         = readAndValidateLockNVIndexPublic
	ReadPcrPolicyCounter                     = readPcrPolicyCounter
	ReadShimVendorCert                       = readShimVendorCert
	WinCertTypePKCSSignedData                = winCertTypePKCSSignedData
	WinCertTypeEfiGuid                       = winCertTypeEfiGuid
)

// Alias some unexported types for testing. These are required in order to pass these between functions in tests, or to access
// unexported members of some unexported types.
type PcrPolicyData = pcrPolicyData

func (d *PcrPolicyData) PCRs() tpm2.PCRSelectionList {
	return d.pcrs
}

func (d *PcrPolicyData) OrData() policyOrDataTree {
	return d.orData
}

func (d *PcrPolicyData) PolicyCount() uint64 {
	return d.policyCount
}

func (d *PcrPolicyData) SetPolicyCount(c uint64) {
	d.policyCount = c
}

func (d *PcrPolicyData) AuthorizedPolicy() tpm2.Digest {
	return d.authorizedPolicy
}

func (d *PcrPolicyData) AuthorizedPolicySignature() *tpm2.Signature {
	return d.authorizedPolicySignature
}

func (d *PcrPolicyData) ExecuteAssertions(tpm *tpm2.TPMContext, policySession tpm2.SessionContext, version uint32, staticData *StaticPolicyData, pin string, hmacSession tpm2.SessionContext) error {
	return d.executeAssertions(tpm, policySession, version, staticData, pin, hmacSession)
}

type EFISignatureData efiSignatureData

func (s *EFISignatureData) SignatureType() *tcglog.EFIGUID {
	return &s.signatureType
}

func (s *EFISignatureData) Owner() *tcglog.EFIGUID {
	return &s.owner
}

func (s *EFISignatureData) Data() []byte {
	return s.data
}

type SecureBootVerificationEvent = secureBootVerificationEvent

func (e *SecureBootVerificationEvent) MeasuredInPreOS() bool {
	return e.measuredInPreOS
}

type SigDbUpdateQuirkMode = sigDbUpdateQuirkMode

type StaticPolicyData = staticPolicyData

func (d *StaticPolicyData) AuthPublicKey() *tpm2.Public {
	return d.authPublicKey
}

func (d *StaticPolicyData) PcrPolicyCounterHandle() tpm2.Handle {
	return d.pcrPolicyCounterHandle
}

func (d *StaticPolicyData) SetPcrPolicyCounterHandle(h tpm2.Handle) {
	d.pcrPolicyCounterHandle = h
}

func (d *StaticPolicyData) V0PinIndexAuthPolicies() tpm2.DigestList {
	return d.v0PinIndexAuthPolicies
}

type WinCertificate interface {
	ToWinCertificateAuthenticode() *WinCertificateAuthenticode
	ToWinCertificateUefiGuid() *WinCertificateUefiGuid
}

type WinCertificateAuthenticode winCertificateAuthenticode

func (c *winCertificateAuthenticode) ToWinCertificateAuthenticode() *WinCertificateAuthenticode {
	return (*WinCertificateAuthenticode)(c)
}

func (c *winCertificateAuthenticode) ToWinCertificateUefiGuid() *WinCertificateUefiGuid {
	return nil
}

type WinCertificateUefiGuid winCertificateUefiGuid

func (c *winCertificateUefiGuid) ToWinCertificateAuthenticode() *WinCertificateAuthenticode {
	return nil
}

func (c *winCertificateUefiGuid) ToWinCertificateUefiGuid() *WinCertificateUefiGuid {
	return (*WinCertificateUefiGuid)(c)
}

// Export some helpers for testing.
func GetWinCertificateType(cert winCertificate) uint16 {
	return cert.wCertificateType()
}

type MockPolicyPCRParam struct {
	PCR     int
	Alg     tpm2.HashAlgorithmId
	Digests tpm2.DigestList
}

// MakeMockPolicyPCRValuesFull computes a slice of tpm2.PCRValues for every combination of supplied PCR values.
func MakeMockPolicyPCRValuesFull(params []MockPolicyPCRParam) (out []tpm2.PCRValues) {
	indices := make([]int, len(params))
	advanceIndices := func() bool {
		for i := range params {
			indices[i]++
			if indices[i] < len(params[i].Digests) {
				break
			}
			indices[i] = 0
			if i == len(params)-1 {
				return false
			}
		}
		return true
	}

	for {
		v := make(tpm2.PCRValues)
		for i := range params {
			v.SetValue(params[i].Alg, params[i].PCR, params[i].Digests[indices[i]])
		}
		out = append(out, v)

		if len(params) == 0 {
			break
		}

		if !advanceIndices() {
			break
		}
	}
	return
}

func MockRunDir(path string) (restore func()) {
	origRunDir := runDir
	runDir = path
	return func() {
		runDir = origRunDir
	}
}

func MockSystemdCryptsetupPath(path string) (restore func()) {
	origSystemdCryptsetupPath := systemdCryptsetupPath
	systemdCryptsetupPath = path
	return func() {
		systemdCryptsetupPath = origSystemdCryptsetupPath
	}
}

func NewPcrPolicyComputeParams(key *ecdsa.PrivateKey, signAlg tpm2.HashAlgorithmId, pcrs tpm2.PCRSelectionList, digests tpm2.DigestList, policyCounterName tpm2.Name, policyCount uint64) *pcrPolicyComputeParams {
	return &pcrPolicyComputeParams{
		key:               key,
		signAlg:           signAlg,
		pcrs:              pcrs,
		digests:           digests,
		policyCounterName: policyCounterName,
		policyCount:       policyCount}
}

func NewStaticPolicyComputeParams(key *tpm2.Public, pcrPolicyCounterPub *tpm2.NVPublic, lockIndexName tpm2.Name) *staticPolicyComputeParams {
	return &staticPolicyComputeParams{key: key, pcrPolicyCounterPub: pcrPolicyCounterPub, lockIndexName: lockIndexName}
}

func (p *PCRProtectionProfile) ComputePCRDigests(tpm *tpm2.TPMContext, alg tpm2.HashAlgorithmId) (tpm2.PCRSelectionList, tpm2.DigestList, error) {
	return p.computePCRDigests(tpm, alg)
}

func (p *PCRProtectionProfile) DumpValues(tpm *tpm2.TPMContext) string {
	values, err := p.computePCRValues(tpm)
	if err != nil {
		return ""
	}
	var s bytes.Buffer
	fmt.Fprintf(&s, "\n")
	for i, v := range values {
		fmt.Fprintf(&s, "Value %d:\n", i)
		for alg := range v {
			for pcr := range v[alg] {
				fmt.Fprintf(&s, " PCR%d,%v: %x\n", pcr, alg, v[alg][pcr])
			}
		}
	}
	return s.String()
}

func (k *SealedKeyObject) SetVersion(version uint32) {
	k.data.version = version
}

func (k *SealedKeyObject) KeyPublic() *tpm2.Public {
	return k.data.keyPublic
}

func (k *SealedKeyObject) SetPCRPolicyCounterHandle(h tpm2.Handle) {
	k.data.staticPolicyData.pcrPolicyCounterHandle = h
}

func (k *SealedKeyObject) AuthPublicKey() *tpm2.Public {
	return k.data.staticPolicyData.authPublicKey
}
