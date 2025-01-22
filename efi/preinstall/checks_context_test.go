// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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

package preinstall_test

import (
	"context"
	"crypto"
	"fmt"
	"io"

	"github.com/canonical/cpuid"
	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"
	secboot_efi "github.com/snapcore/secboot/efi"
	. "github.com/snapcore/secboot/efi/preinstall"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
	pe "github.com/snapcore/secboot/internal/pe1.14"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type runChecksContextSuite struct {
	tpm2_testutil.TPMSimulatorTest
	tpmPropertyModifierMixin
	tcglogReplayMixin
}

func (s *runChecksContextSuite) SetUpTest(c *C) {
	s.TPMSimulatorTest.SetUpTest(c)
	s.tpmPropertyModifierMixin.transport = s.Transport
	s.tcglogReplayMixin.impl = s
}

func (s *runChecksContextSuite) Tpm() *tpm2.TPMContext {
	return s.TPM
}

var _ = Suite(&runChecksContextSuite{})

type testRunChecksContextRunParams struct {
	env                  internal_efi.HostEnvironment
	tpmPropertyModifiers map[tpm2.Property]uint32
	enabledBanks         []tpm2.HashAlgorithmId
	prepare              func()

	initialFlags CheckFlags
	loadedImages []secboot_efi.Image
	profileOpts  PCRProfileOptionsFlags

	action     Action
	actionArgs []any

	expectedPcrAlg                   tpm2.HashAlgorithmId
	expectedUsedSecureBootCAs        []*X509CertificateID
	expectedFlags                    CheckResultFlags
	expectedWarningsMatch            string
	expectedIntermediateErrorMatches []string
}

func (s *runChecksContextSuite) testRun(c *C, params *testRunChecksContextRunParams) []*ErrorKindAndActions {
	s.allocatePCRBanks(c, params.enabledBanks...)
	log, err := params.env.ReadEventLog()
	c.Assert(err, IsNil)
	s.resetTPMAndReplayLog(c, log, log.Algorithms...)
	s.addTPMPropertyModifiers(c, params.tpmPropertyModifiers)

	restore := MockEfiComputePeImageDigest(func(alg crypto.Hash, r io.ReaderAt, sz int64) ([]byte, error) {
		c.Check(alg, Equals, params.expectedPcrAlg.GetHash())
		c.Assert(r, testutil.ConvertibleTo, &mockImageReader{})
		imageReader := r.(*mockImageReader)
		c.Check(sz, Equals, int64(len(imageReader.contents)))
		return imageReader.digest, nil
	})

	restore = MockRunChecksEnv(params.env)
	defer restore()

	restore = MockInternalEfiSecureBootSignaturesFromPEFile(func(pefile *pe.File, r io.ReaderAt) ([]*efi.WinCertificateAuthenticode, error) {
		c.Assert(r, testutil.ConvertibleTo, &mockImageReader{})
		imageReader := r.(*mockImageReader)
		return imageReader.signatures, nil
	})
	defer restore()

	restore = MockPeNewFile(func(r io.ReaderAt) (*pe.File, error) {
		return new(pe.File), nil
	})
	defer restore()

	if params.prepare != nil {
		params.prepare()
	}

	ctx := NewRunChecksContext(params.initialFlags, params.loadedImages, params.profileOpts)
	c.Assert(ctx, NotNil)

	result, errs := ctx.Run(context.Background(), params.action, params.actionArgs...)
	if len(errs) > 0 {
		for i, err := range errs {
			fmt.Println("errno", i, ":", err.Error)
		}
		return errs
	}

	c.Check(result.PCRAlg, Equals, params.expectedPcrAlg)
	c.Assert(result.UsedSecureBootCAs, HasLen, len(params.expectedUsedSecureBootCAs))
	for i, ca := range result.UsedSecureBootCAs {
		c.Check(ca, DeepEquals, params.expectedUsedSecureBootCAs[i])
	}
	c.Check(result.Flags, Equals, params.expectedFlags)
	c.Check(result.Warnings, ErrorMatches, params.expectedWarningsMatch)

	c.Check(ctx.Result(), DeepEquals, result)

	c.Assert(ctx.Errors(), HasLen, len(params.expectedIntermediateErrorMatches))
	for i, err := range ctx.Errors() {
		c.Check(err, ErrorMatches, params.expectedIntermediateErrorMatches[i])
	}
	if len(params.expectedIntermediateErrorMatches) > 0 {
		c.Check(ctx.LastError(), ErrorMatches, params.expectedIntermediateErrorMatches[len(params.expectedIntermediateErrorMatches)-1])
	}

	dev, err := params.env.TPMDevice()
	c.Assert(err, IsNil)
	c.Assert(dev, testutil.ConvertibleTo, &tpm2_testutil.TransportBackedDevice{})
	c.Check(dev.(*tpm2_testutil.TransportBackedDevice).NumberOpen(), Equals, 0)

	return nil
}

func (s *runChecksContextSuite) TestRunGood(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:               PCRProfileOptionsDefault,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `one or more errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

func (s *runChecksContextSuite) TestRunGoodSHA384(c *C) {
	s.RequireAlgorithm(c, tpm2.AlgorithmSHA384)

	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "030ac3c913dab858f1d69239115545035cff671d6229f95577bb0ffbd827b35abaf6af6bfd223e04ecc9b60a9803642d"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "6c2df9007211786438be210b6908f2935d0b25ebdcd2c65621826fd2ec55fb9fbacbfe080d48db98f0ef970273b8254a")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "42f61b3089f5ce0646b422a59c9632065db2630f3e5b01690e63c41420ed31f10ff2a191f3440f9501109fc85f7fb00f")},
		},
		profileOpts:               PCRProfileOptionsDefault,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA384,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `one or more errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

func (s *runChecksContextSuite) TestRunGoodSHA1(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA1}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA1},
		initialFlags: PermitWeakPCRBanks,
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25b4e4624ea1f2144a90d7de7aff87b23de0457d"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "1dc8bcbdb8b5ee60e87281e36161ec1f923f53b7")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "fc7840d38322a595e50a6b477685fdd2244f9292")},
		},
		profileOpts:               PCRProfileOptionsDefault,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA1,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `one or more errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

// TODO: Test a good case with an empty SHA-384 bank when we have an action to turn on the PermitEmptyPCRBanks flag

func (s *runChecksContextSuite) TestRunGoodPostInstall(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     6,
			tpm2.PropertyNVCounters:        5,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		initialFlags: PostInstallChecks,
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:               PCRProfileOptionsDefault,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `one or more errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

// TODO: Test a good case with a VM setup when we have an action to turn on the PermitVirtualMachine flag.
// TODO: Test a good case with a discrete TPM where the startup locality is not protected, when we have an action to turn on the PermitNoDiscreteTPMResetMitigation flag.

func (s *runChecksContextSuite) TestRunGoodDiscreteTPMDetectedSL3(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				StartupLocality: 3,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:               PCRProfileOptionsDefault,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | DiscreteTPMDetected,
		expectedWarningsMatch: `one or more errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

// TODO: Test a good case with a discrete TPM where the startup locality is 3, but not protected, when we have an action to turn on the PermitNoDiscreteTPMResetMitigation flag.

func (s *runChecksContextSuite) TestRunGoodDiscreteTPMDetectedHCRTM(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				StartupLocality: 4,
			})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerNTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:               PCRProfileOptionsDefault,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | DiscreteTPMDetected,
		expectedWarningsMatch: `one or more errors detected:
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

// TODO: Test a good case with a discrete TPM where there is a HCRTM event but startup locality is 4 is not protected, when we have an action to turn on the PermitNoDiscreteTPMResetMitigation flag.

func (s *runChecksContextSuite) TestRunInvalidPCR0Value(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		prepare: func() {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(0), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:               PCRProfileOptionsDefault,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformFirmwareProfileSupport | NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `one or more errors detected:
- error with platform firmware \(PCR0\) measurements: PCR value mismatch \(actual from TPM 0xe9995745ca25279ec699688b70488116fe4d9f053cb0991dd71e82e7edfa66b5, reconstructed from log 0xa6602a7a403068b5556e78cc3f5b00c9c76d33d514093ca9b584dce7590e6c69\)
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}

func (s *runChecksContextSuite) TestRunInvalidPCR2Value(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}

	errs := s.testRun(c, &testRunChecksContextRunParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithVirtMode(internal_efi.VirtModeNone, internal_efi.DetectVirtModeAll),
			efitest.WithTPMDevice(tpm2_testutil.NewTransportBackedDevice(s.Transport, false, 1)),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
			efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
			efitest.WithSysfsDevices(devices),
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
		),
		tpmPropertyModifiers: map[tpm2.Property]uint32{
			tpm2.PropertyNVCountersMax:     0,
			tpm2.PropertyPSFamilyIndicator: 1,
			tpm2.PropertyManufacturer:      uint32(tpm2.TPMManufacturerINTC),
		},
		enabledBanks: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		prepare: func() {
			_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(2), []byte("foo"), nil)
			c.Check(err, IsNil)
		},
		loadedImages: []secboot_efi.Image{
			&mockImage{
				contents: []byte("mock shim executable"),
				digest:   testutil.DecodeHexString(c, "25e1b08db2f31ff5f5d2ea53e1a1e8fda6e1d81af4f26a7908071f1dec8611b7"),
				signatures: []*efi.WinCertificateAuthenticode{
					efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
				},
			},
			&mockImage{contents: []byte("mock grub executable"), digest: testutil.DecodeHexString(c, "d5a9780e9f6a43c2e53fe9fda547be77f7783f31aea8013783242b040ff21dc0")},
			&mockImage{contents: []byte("mock kernel executable"), digest: testutil.DecodeHexString(c, "2ddfbd91fa1698b0d133c38ba90dbba76c9e08371ff83d03b5fb4c2e56d7e81f")},
		},
		profileOpts:               PCRProfileOptionTrustCAsForVARSuppliedDrivers,
		action:                    ActionNone,
		expectedPcrAlg:            tpm2.HashAlgorithmSHA256,
		expectedUsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		expectedFlags:             NoPlatformConfigProfileSupport | NoDriversAndAppsProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		expectedWarningsMatch: `one or more errors detected:
- error with drivers and apps \(PCR2\) measurements: PCR value mismatch \(actual from TPM 0xfa734a6a4d262d7405d47d48c0a1b127229ca808032555ad919ed5dd7c1f6519, reconstructed from log 0x3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969\)
- error with platform config \(PCR1\) measurements: generating profiles for PCR 1 is not supported yet
- error with drivers and apps config \(PCR3\) measurements: generating profiles for PCR 3 is not supported yet
- error with boot manager config \(PCR5\) measurements: generating profiles for PCR 5 is not supported yet
`,
	})
	c.Check(errs, HasLen, 0)
}
