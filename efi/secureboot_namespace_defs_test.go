// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2023 Canonical Ltd
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

package efi_test

import (
	efi "github.com/canonical/go-efilib"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
)

type secureBootNamespaceDefsSuite struct {
	restoreNewShimImageHandle func()
	mockShimImageHandleMixin
}

var _ = Suite(&secureBootNamespaceDefsSuite{})

func (s *secureBootNamespaceDefsSuite) TestNewOrExistingUbuntuShim15_7(c *C) {
	// Verify we get a correctly configured shimLoadHandler for the Ubuntu shim 15.7
	image := newMockUbuntuShimImage15_7(c)

	rules := MakeSecureBootNamespaceRules()
	handler, err := rules.NewOrExisting(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &ShimLoadHandler{})

	shimHandler := handler.(*ShimLoadHandler)
	c.Check(shimHandler.Flags, Equals, ShimHasSbatVerification|ShimFixVariableAuthorityEventsMatchSpec|ShimVendorCertContainsDb|ShimHasSbatRevocationManagement)
	c.Check(shimHandler.VendorDb, DeepEquals, &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "MokListRT", GUID: ShimGuid},
		Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, ShimGuid)},
	})
	c.Check(shimHandler.SbatLevel, DeepEquals, ShimSbatLevel{[]byte("sbat,1,2022111500\nshim,2\ngrub,3\n"), []byte("sbat,1,2022052400\ngrub,2\n")})
}

func (s *secureBootNamespaceDefsSuite) TestNewOrExistingUbuntuShim15_4(c *C) {
	// Verify we get a correctly configured shimLoadHandler for the Ubuntu shim 15.4
	image := newMockUbuntuShimImage15_4(c)

	rules := MakeSecureBootNamespaceRules()
	handler, err := rules.NewOrExisting(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &ShimLoadHandler{})

	shimHandler := handler.(*ShimLoadHandler)
	c.Check(shimHandler.Flags, Equals, ShimHasSbatVerification|ShimFixVariableAuthorityEventsMatchSpec)
	c.Check(shimHandler.VendorDb, DeepEquals, &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
		Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})},
	})
	c.Check(shimHandler.SbatLevel, DeepEquals, ShimSbatLevel{[]byte("sbat,1,2021030218\n"), []byte("sbat,1,2021030218\n")})
}

func (s *secureBootNamespaceDefsSuite) TestNewOrExistingUbuntuShim15WithFixes1(c *C) {
	// Verify we get a correctly configured shimLoadHandler for the Ubuntu shim 15 with
	// the required fixes (1.41+15+1552672080.a4a1fbe-0ubuntu1)
	image := newMockUbuntuShimImage15a(c)

	rules := MakeSecureBootNamespaceRules()
	handler, err := rules.NewOrExisting(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &ShimLoadHandler{})

	shimHandler := handler.(*ShimLoadHandler)
	c.Check(shimHandler.Flags, Equals, ShimFlags(0))
	c.Check(shimHandler.VendorDb, DeepEquals, &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
		Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})},
	})
	c.Check(shimHandler.SbatLevel, DeepEquals, ShimSbatLevel{})
}

func (s *secureBootNamespaceDefsSuite) TestNewOrExistingUbuntuShim15WithFixes2(c *C) {
	// Verify we get a correctly configured shimLoadHandler for the Ubuntu shim 15 with
	// the required fixes (1.40.4+15+1552672080.a4a1fbe-0ubuntu2)
	image := newMockUbuntuShimImage15b(c)

	rules := MakeSecureBootNamespaceRules()
	handler, err := rules.NewOrExisting(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &ShimLoadHandler{})

	shimHandler := handler.(*ShimLoadHandler)
	c.Check(shimHandler.Flags, Equals, ShimFlags(0))
	c.Check(shimHandler.VendorDb, DeepEquals, &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
		Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})},
	})
	c.Check(shimHandler.SbatLevel, DeepEquals, ShimSbatLevel{})
}

func (s *secureBootNamespaceDefsSuite) TestNewOrExistingUbuntuGrubSbat(c *C) {
	// Verify we get a correctly configured grubLoadHandler for the Ubuntu grub
	image := newMockUbuntuGrubImage3(c)

	rules := MakeSecureBootNamespaceRules()
	AddSecureBootNamespaceDelegatedAuthority(rules, testutil.ParseCertificate(c, msUefiCACert), testutil.ParseCertificate(c, canonicalCACert))
	handler, err := rules.NewOrExisting(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &GrubLoadHandler{})

	c.Check(handler.(*GrubLoadHandler).Flags, Equals, GrubChainloaderUsesShimProtocol)
}

func (s *secureBootNamespaceDefsSuite) TestNewOrExistingUbuntuGrubNoSbat(c *C) {
	// Verify we get a correctly configured grubLoadHandler for the Ubuntu grub (pre-SBAT)
	image := newMockUbuntuGrubImage1(c)

	rules := MakeSecureBootNamespaceRules()
	AddSecureBootNamespaceDelegatedAuthority(rules, testutil.ParseCertificate(c, msUefiCACert), testutil.ParseCertificate(c, canonicalCACert))
	handler, err := rules.NewOrExisting(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &GrubLoadHandler{})

	c.Check(handler.(*GrubLoadHandler).Flags, Equals, GrubChainloaderUsesShimProtocol)
}

func (s *secureBootNamespaceDefsSuite) TestNewOrExistingUbuntuUKISbat(c *C) {
	// Verify that we get a ubuntuCoreUKIHandler for an Ubuntu Core kernel image
	image := newMockUbuntuKernelImage3(c)

	rules := MakeSecureBootNamespaceRules()
	AddSecureBootNamespaceDelegatedAuthority(rules, testutil.ParseCertificate(c, msUefiCACert), testutil.ParseCertificate(c, canonicalCACert))
	handler, err := rules.NewOrExisting(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &UbuntuCoreUKILoadHandler{})
}

func (s *secureBootNamespaceDefsSuite) TestNewOrExistingUbuntuUKINoSbat(c *C) {
	// Verify that we get a ubuntuCoreUKIHandler for an Ubuntu Core kernel image (pre-SBAT)
	image := newMockUbuntuKernelImage1(c)

	rules := MakeSecureBootNamespaceRules()
	AddSecureBootNamespaceDelegatedAuthority(rules, testutil.ParseCertificate(c, msUefiCACert), testutil.ParseCertificate(c, canonicalCACert))
	handler, err := rules.NewOrExisting(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &UbuntuCoreUKILoadHandler{})
}

func (s *secureBootNamespaceDefsSuite) TestNewOrExistingUbuntuTreatsCanonicalCAAsMSUefiCA(c *C) {
	// Verify that the Canonical CA cert is recognized as part of the MS UEFI CA namespace.
	image := newMockUbuntuShimImage15_7(c)

	rules := MakeSecureBootNamespaceRules()
	handler, err := rules.NewOrExisting(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &ShimLoadHandler{})

	// Verify that looking up Ubuntu grub returns a correctly configured load handler
	// (not from the fallback namespace)
	image2 := newMockUbuntuGrubImage3(c)
	handler, err = rules.NewOrExisting(image2.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &GrubLoadHandler{})

	c.Check(handler.(*GrubLoadHandler).Flags, Equals, GrubChainloaderUsesShimProtocol)
}

func (s *secureBootNamespaceDefsSuite) TestNewOrExistingUbuntuGrubFromFallback(c *C) {
	// Verify that the fallback namespace works for components that are unrecognized.
	image := newMockUbuntuGrubImage3(c)

	rules := MakeSecureBootNamespaceRules()
	handler, err := rules.NewOrExisting(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &GrubLoadHandler{})

	c.Check(handler.(*GrubLoadHandler).Flags, Equals, GrubFlags(0))
}

func (s *secureBootNamespaceDefsSuite) TestNewOrExistingCached(c *C) {
	// Verify that calling NewOrExisting multiple times with the same image returns
	// the same handler.
	image := newMockUbuntuShimImage15_7(c)

	rules := MakeSecureBootNamespaceRules()
	handler, err := rules.NewOrExisting(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &ShimLoadHandler{})

	handler2, err := rules.NewOrExisting(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler2, Equals, handler)
}
