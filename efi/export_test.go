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

package efi

import (
	"bytes"
	"crypto/x509"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/tcglog-parser"
	"github.com/snapcore/secboot/internal/testutil"
)

// Export constants for testing
const (
	BootManagerCodeProfile                     = bootManagerCodeProfile
	GrubChainloaderUsesShimProtocol            = grubChainloaderUsesShimProtocol
	SecureBootPolicyProfile                    = secureBootPolicyProfile
	ShimFixVariableAuthorityEventsMatchSpec    = shimFixVariableAuthorityEventsMatchSpec
	ShimHasSbatRevocationManagement            = shimHasSbatRevocationManagement
	ShimHasSbatVerification                    = shimHasSbatVerification
	ShimName                                   = shimName
	ShimSbatPolicyLatest                       = shimSbatPolicyLatest
	ShimSbatPolicyPrevious                     = shimSbatPolicyPrevious
	ShimVendorCertContainsDb                   = shimVendorCertContainsDb
	ShimVendorCertIsX509                       = shimVendorCertIsX509
	ShimVendorCertIsDb                         = shimVendorCertIsDb
	SignatureDBUpdateNoFirmwareQuirk           = signatureDBUpdateNoFirmwareQuirk
	SignatureDBUpdateFirmwareDedupIgnoresOwner = signatureDBUpdateFirmwareDedupIgnoresOwner
)

// Export variables and unexported functions for testing
var (
	ApplySignatureDBUpdate        = applySignatureDBUpdate
	DefaultEnv                    = defaultEnv
	MakeSecureBootNamespaceRules  = makeSecureBootNamespaceRules
	MustParseShimVersion          = mustParseShimVersion
	NewestSbatLevel               = newestSbatLevel
	NewFwLoadHandler              = newFwLoadHandler
	NewOrExistingImageLoadHandler = newOrExistingImageLoadHandler
	NewPcrBranchContextImpl       = newPcrBranchContextImpl
	NewPcrImagesMeasurer          = newPcrImagesMeasurer
	NewPcrProfileGenerator        = newPcrProfileGenerator
	NewRootVarsCollector          = newRootVarsCollector
	NewShimImageHandle            = newShimImageHandle
	NewShimLoadHandler            = newShimLoadHandler
	NewShimLoadHandlerConstructor = newShimLoadHandlerConstructor
	OpenPeImage                   = openPeImage
	ParseShimVersion              = parseShimVersion
	ParseShimVersionDataIdent     = parseShimVersionDataIdent
	ReadShimSbatPolicy            = readShimSbatPolicy
	ShimGuid                      = shimGuid
)

// Alias some unexported types for testing. These are required in order to pass these between functions in tests, or to access
// unexported members of some unexported types.
type FwContext = fwContext
type GrubFlags = grubFlags
type GrubLoadHandler = grubLoadHandler
type ImageLoadHandler = imageLoadHandler
type ImageLoadHandlers = imageLoadHandlers
type ImageLoadParamsSet = imageLoadParamsSet
type LoadParams = loadParams
type PcrBranchContext = pcrBranchContext
type PcrImagesMeasurer = pcrImagesMeasurer
type PcrProfileContext = pcrProfileContext
type PcrProfileFlags = pcrProfileFlags
type PeImageHandle = peImageHandle
type RootVarReaderKey = rootVarReaderKey
type RootVarsCollector = rootVarsCollector
type SbatComponent = sbatComponent
type SecureBootAuthority = secureBootAuthority
type SecureBootDB = secureBootDB
type SecureBootNamespaceRules = secureBootNamespaceRules
type SecureBootPolicyMixin = secureBootPolicyMixin
type ShimContext = shimContext
type ShimFlags = shimFlags
type ShimImageHandle = shimImageHandle
type ShimLoadHandler = shimLoadHandler
type ShimSbatLevel = shimSbatLevel
type ShimSbatPolicy = shimSbatPolicy
type ShimVendorCertFormat = shimVendorCertFormat
type ShimVersion = shimVersion
type SignatureDBUpdateFirmwareQuirk = signatureDBUpdateFirmwareQuirk
type UbuntuCoreUKILoadHandler = ubuntuCoreUKILoadHandler
type VarBranch = varBranch
type VarReadWriter = varReadWriter

// Helper functions
func AddSecureBootNamespaceDelegatedAuthority(rules SecureBootNamespaceRules, orig, delegated *x509.Certificate) {
	for _, ns := range rules.(*secureBootNamespaceRulesImpl).namespaces {
		for _, authority := range ns.authorities {
			if bytes.Equal(authority.subject, orig.RawSubject) && bytes.Equal(authority.subjectKeyId, orig.SubjectKeyId) && authority.publicKeyAlgorithm == orig.PublicKeyAlgorithm {
				ns.AddAuthority(delegated)
				return
			}
		}
	}
}

func ImageLoadActivityNext(activity ImageLoadActivity) []ImageLoadActivity {
	return activity.next()
}

func ImageLoadActivityParams(activity ImageLoadActivity) imageLoadParamsSet {
	return activity.params()
}

func (s *ImageLoadSequences) Images() []ImageLoadActivity {
	return s.images
}

func (s *ImageLoadSequences) Params() imageLoadParamsSet {
	return s.params
}

func MockEFIVarsPath(path string) (restore func()) {
	origPath := efiVarsPath
	efiVarsPath = path
	return func() {
		efiVarsPath = origPath
	}
}

func MockEventLogPath(path string) (restore func()) {
	origPath := eventLogPath
	eventLogPath = path
	return func() {
		eventLogPath = origPath
	}
}

func MockNewFwLoadHandler(fn func(*tcglog.Log) ImageLoadHandler) (restore func()) {
	orig := newFwLoadHandler
	newFwLoadHandler = fn
	return func() {
		newFwLoadHandler = orig
	}
}

func MockNewShimImageHandle(fn func(peImageHandle) shimImageHandle) (restore func()) {
	orig := newShimImageHandle
	newShimImageHandle = fn
	return func() {
		newShimImageHandle = orig
	}
}

func MockOpenPeImage(fn func(Image) (peImageHandle, error)) (restore func()) {
	orig := openPeImage
	openPeImage = fn
	return func() {
		openPeImage = orig
	}
}

func MockReadVar(dir string) (restore func()) {
	origReadVar := readVar
	readVar = func(name string, guid efi.GUID) ([]byte, efi.VariableAttributes, error) {
		return testutil.EFIReadVar(dir, name, guid)
	}

	return func() {
		readVar = origReadVar
	}
}

func MockMakeSecureBootNamespaceRules(fn func() secureBootNamespaceRules) (restore func()) {
	orig := makeSecureBootNamespaceRules
	makeSecureBootNamespaceRules = fn
	return func() {
		makeSecureBootNamespaceRules = orig
	}
}

func NewRootVarReader(host HostEnvironment) *rootVarReader {
	return &rootVarReader{
		host:      host,
		overrides: make(map[efi.VariableDescriptor]varContents)}
}

func NewVarUpdate(prev *varUpdate, name efi.VariableDescriptor, attrs efi.VariableAttributes, data []byte) *varUpdate {
	return &varUpdate{
		previous: prev,
		name:     name,
		attrs:    attrs,
		data:     data}
}
