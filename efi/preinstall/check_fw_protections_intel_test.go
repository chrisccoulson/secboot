//go:build amd64

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
	"bytes"
	"io"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/efi/preinstall"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
)

type fwProtectionsIntelSuite struct{}

var _ = Suite(&fwProtectionsIntelSuite{})

type mockMEISysfsDevice struct {
	fwVer    []byte
	fwStatus []byte
}

func (*mockMEISysfsDevice) Name() string      { return "mei0" }
func (*mockMEISysfsDevice) Path() string      { return "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0" }
func (*mockMEISysfsDevice) Subsystem() string { return "mei" }

func (d *mockMEISysfsDevice) AttributeReader(attr string) (io.ReadCloser, error) {
	switch attr {
	case "fw_ver":
		if len(d.fwVer) == 0 {
			return nil, internal_efi.ErrNoDeviceAttribute
		}
		return io.NopCloser(bytes.NewReader(d.fwVer)), nil
	case "fw_status":
		if len(d.fwStatus) == 0 {
			return nil, internal_efi.ErrNoDeviceAttribute
		}
		return io.NopCloser(bytes.NewReader(d.fwStatus)), nil
	default:
		return nil, internal_efi.ErrNoDeviceAttribute
	}
}

func regPtrs(regs *[6]uint32) (out [6]*uint32) {
	for i := range *regs {
		out[i] = &((*regs)[i])
	}
	return out
}

func (s *fwProtectionsIntelSuite) TestReadIntelHFSTSRegistersFromMEISysfs1(c *C) {
	dev := &mockMEISysfsDevice{
		fwStatus: []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}

	var regs [6]uint32
	err := ReadIntelHFSTSRegistersFromMEISysfs(dev, regPtrs(&regs))
	c.Check(err, IsNil)
	c.Check(regs, Equals, [6]uint32{
		0x94000245,
		0x09F10506,
		0x00000020,
		0x00004000,
		0x00041F03,
		0xC7E003CB,
	})
}

func (s *fwProtectionsIntelSuite) TestReadIntelHFSTSRegistersFromMEISysfs2(c *C) {
	dev := &mockMEISysfsDevice{
		fwStatus: []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E0034B
`),
	}

	var regs [6]uint32
	err := ReadIntelHFSTSRegistersFromMEISysfs(dev, regPtrs(&regs))
	c.Check(err, IsNil)
	c.Check(regs, Equals, [6]uint32{
		0x94000245,
		0x09F10506,
		0x00000020,
		0x00004000,
		0x00041F03,
		0xC7E0034B,
	})
}

func (s *fwProtectionsIntelSuite) TestReadIntelHFSTSRegistersFromMEISysfsErrNoAttr(c *C) {
	dev := &mockMEISysfsDevice{}

	var regs [6]uint32
	err := ReadIntelHFSTSRegistersFromMEISysfs(dev, regPtrs(&regs))
	c.Check(err, ErrorMatches, `device attribute does not exist`)
}

func (s *fwProtectionsIntelSuite) TestReadIntelHFSTSRegistersFromMEISysfsErrTooMany(c *C) {
	dev := &mockMEISysfsDevice{
		fwStatus: []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
00000000
`),
	}

	var regs [6]uint32
	err := ReadIntelHFSTSRegistersFromMEISysfs(dev, regPtrs(&regs))
	c.Check(err, ErrorMatches, `invalid fw_status format: too many entries`)
}

func (s *fwProtectionsIntelSuite) TestReadIntelHFSTSRegistersFromMEISysfsErrInvalidLineLen(c *C) {
	dev := &mockMEISysfsDevice{
		fwStatus: []byte(`94000245
09F10506
00000020
00004000
00041F03
7E003CB
`),
	}

	var regs [6]uint32
	err := ReadIntelHFSTSRegistersFromMEISysfs(dev, regPtrs(&regs))
	c.Check(err, ErrorMatches, `invalid fw_status format: unexpected line length for line 5 \(7 chars\)`)
}

func (s *fwProtectionsIntelSuite) TestReadIntelHFSTSRegistersFromMEISysfsErrInvalidLine(c *C) {
	dev := &mockMEISysfsDevice{
		fwStatus: []byte(`94000245
09F10506
00000020
00004000
00041F03
G7E003CB
`),
	}

	var regs [6]uint32
	err := ReadIntelHFSTSRegistersFromMEISysfs(dev, regPtrs(&regs))
	c.Check(err, ErrorMatches, `invalid fw_status format: cannot scan line 5: expected integer`)
}

func (s *fwProtectionsIntelSuite) TestReadIntelHFSTSRegistersFromMEISysfsErrNotEnough(c *C) {
	dev := &mockMEISysfsDevice{
		fwStatus: []byte(`94000245
09F10506
00000020
00004000
00041F03
`),
	}

	var regs [6]uint32
	err := ReadIntelHFSTSRegistersFromMEISysfs(dev, regPtrs(&regs))
	c.Check(err, ErrorMatches, `invalid fw_status format: not enough entries`)
}

func (s *fwProtectionsIntelSuite) TestReadIntelMeVersionFromMEISysfs1(c *C) {
	dev := &mockMEISysfsDevice{
		fwVer: []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
	}

	ver, err := ReadIntelMEVersionFromMEISysfs(dev)
	c.Check(err, IsNil)
	c.Check(ver, DeepEquals, MeVersion{
		Platform: 0,
		Major:    16,
		Minor:    1,
		Hotfix:   27,
		Buildno:  2176,
	})
}

func (s *fwProtectionsIntelSuite) TestReadIntelMeVersionFromMEISysfs2(c *C) {
	dev := &mockMEISysfsDevice{
		fwVer: []byte(`0:8.1.65.1586
0:8.1.65.1586
0:8.1.52.1496
`),
	}

	ver, err := ReadIntelMEVersionFromMEISysfs(dev)
	c.Check(err, IsNil)
	c.Check(ver, DeepEquals, MeVersion{
		Platform: 0,
		Major:    8,
		Minor:    1,
		Hotfix:   65,
		Buildno:  1586,
	})
}

func (s *fwProtectionsIntelSuite) TestReadIntelMeVersionFromMEISysfsErrNoAttr(c *C) {
	dev := &mockMEISysfsDevice{}
	_, err := ReadIntelMEVersionFromMEISysfs(dev)
	c.Check(err, ErrorMatches, `device attribute does not exist`)
}

func (s *fwProtectionsIntelSuite) TestReadIntelMeVersionFromMEISysfsErrInvalidVer(c *C) {
	dev := &mockMEISysfsDevice{
		fwVer: []byte(`0:16.1.27
0:16.1.27.2176
0:16.0.15.1624
`),
	}
	_, err := ReadIntelMEVersionFromMEISysfs(dev)
	c.Check(err, ErrorMatches, `invalid fw_ver: unexpected EOF`)
}

func (s *fwProtectionsIntelSuite) TestCalculateIntelMEFamilyCSME(c *C) {
	c.Check(CalculateIntelMEFamily(MeVersion{Major: 11}, 0x94000245), Equals, MeFamilyCsme)
}

func (s *fwProtectionsIntelSuite) TestCalculateIntelMEFamilyME(c *C) {
	c.Check(CalculateIntelMEFamily(MeVersion{Major: 9}, 0x94000245), Equals, MeFamilyMe)
}

func (s *fwProtectionsIntelSuite) TestCalculateIntelMEFamilyTXE1(c *C) {
	c.Check(CalculateIntelMEFamily(MeVersion{Major: 5}, 0x94000245), Equals, MeFamilyTxe)
}

func (s *fwProtectionsIntelSuite) TestCalculateIntelMEFamilyTXE2(c *C) {
	c.Check(CalculateIntelMEFamily(MeVersion{Major: 4}, 0x94000245), Equals, MeFamilyTxe)
}

func (s *fwProtectionsIntelSuite) TestCalculateIntelMEFamilySPS(c *C) {
	c.Check(CalculateIntelMEFamily(MeVersion{Major: 4}, 0x940F0245), Equals, MeFamilySps)
}

func (s *fwProtectionsIntelSuite) TestCalculateIntelMEFamilyUnkown(c *C) {
	c.Check(CalculateIntelMEFamily(MeVersion{Major: 0}, 0x940F0245), Equals, MeFamilyUnknown)
}

func (s *fwProtectionsIntelSuite) TestCheckPlatformFirmwareProtectionsMEIGoodCSME(c *C) {
	attrs := map[string][]byte{
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
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", attrs),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices))
	err := CheckPlatformFirmwareProtectionsIntelMEI(env)
	c.Check(err, IsNil)
}

func (s *fwProtectionsIntelSuite) TestCheckPlatformFirmwareProtectionsMEIGoodME(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:8.1.65.1586
0:8.1.65.1586
0:8.1.52.1496
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
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", attrs),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices))
	err := CheckPlatformFirmwareProtectionsIntelMEI(env)
	c.Check(err, IsNil)
}

func (s *fwProtectionsIntelSuite) TestCheckPlatformFirmwareProtectionsMEIGoodSPS(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:4.1.4.54
0:4.1.4.54
0:4.1.4.54
`),
		"fw_status": []byte(`940f0245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", attrs),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices))
	err := CheckPlatformFirmwareProtectionsIntelMEI(env)
	c.Check(err, IsNil)
}

func (s *fwProtectionsIntelSuite) TestCheckPlatformFirmwareProtectionsMEIErrNoDevices(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts()
	err := CheckPlatformFirmwareProtectionsIntelMEI(env)
	c.Check(err, ErrorMatches, `cannot obtain devices with \"mei\" class: nil devices`)
}

func (s *fwProtectionsIntelSuite) TestCheckPlatformFirmwareProtectionsMEIErrNoMEIDevice(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(make(map[string][]internal_efi.SysfsDevice)))
	err := CheckPlatformFirmwareProtectionsIntelMEI(env)
	c.Check(err, ErrorMatches, `no MEI device available`)
}

func (s *fwProtectionsIntelSuite) TestCheckPlatformFirmwareProtectionsMEIErrHFSTSRegisters(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", attrs),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices))
	err := CheckPlatformFirmwareProtectionsIntelMEI(env)
	c.Check(err, ErrorMatches, `cannot read HFSTS registers from sysfs: device attribute does not exist`)
}

func (s *fwProtectionsIntelSuite) TestCheckPlatformFirmwareProtectionsMEIErrFwVer(c *C) {
	attrs := map[string][]byte{
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", attrs),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices))
	err := CheckPlatformFirmwareProtectionsIntelMEI(env)
	c.Check(err, ErrorMatches, `cannot obtain ME version from sysfs: device attribute does not exist`)
}

func (s *fwProtectionsIntelSuite) TestCheckPlatformFirmwareProtectionsMEIErrMfgMode(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000255
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", attrs),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices))
	err := CheckPlatformFirmwareProtectionsIntelMEI(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: ME is in manufacturing mode: no firmware protections are enabled`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *fwProtectionsIntelSuite) TestCheckPlatformFirmwareProtectionsMEIErrOperationMode(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94040245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", attrs),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices))
	err := CheckPlatformFirmwareProtectionsIntelMEI(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: invalid ME operation mode: checks for software tampering may be disabled`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *fwProtectionsIntelSuite) TestCheckPlatformFirmwareProtectionsMEIErrInvalidFamily(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:3.1.70.0
0:3.1.70.0
0:3.1.65.0
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
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", attrs),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices))
	err := CheckPlatformFirmwareProtectionsIntelMEI(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: BootGuard unsupported on TXE ME family`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *fwProtectionsIntelSuite) TestCheckPlatformFirmwareProtectionsMEIErrBootGuardDisable(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
D7E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", attrs),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices))
	err := CheckPlatformFirmwareProtectionsIntelMEI(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: BootGuard is disabled`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *fwProtectionsIntelSuite) TestCheckPlatformFirmwareProtectionsMEIErrNoForceBootGuardACM(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CA
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", attrs),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices))
	err := CheckPlatformFirmwareProtectionsIntelMEI(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: the BootGuard ACM is not forced to execute - the CPU can execute arbitrary code from the legacy reset vector if BootGuard cannot be successfully loaded`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *fwProtectionsIntelSuite) TestCheckPlatformFirmwareProtectionsMEIErrNoVerifiedBoot(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E001CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", attrs),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices))
	err := CheckPlatformFirmwareProtectionsIntelMEI(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: BootGuard verified boot mode is not enabled - this allows arbitrary firmware that doesn't have a valid signature to be executed`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *fwProtectionsIntelSuite) TestCheckPlatformFirmwareProtectionsMEIErrEnforcementPolicy(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E0034B
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", attrs),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices))
	err := CheckPlatformFirmwareProtectionsIntelMEI(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: BootGuard does not have an appropriate error enforcement policy`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *fwProtectionsIntelSuite) TestCheckPlatformFirmwareProtectionsMEIErrNoProtectBIOSEnv(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003C3
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", attrs),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices))
	err := CheckPlatformFirmwareProtectionsIntelMEI(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: the \"Protect BIOS Environment\" feature is not enabled`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *fwProtectionsIntelSuite) TestCheckPlatformFirmwareProtectionsMEIErrNoFPFSOCLock(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
87E003CB
`),
	}
	devices := map[string][]internal_efi.SysfsDevice{
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", attrs),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices))
	err := CheckPlatformFirmwareProtectionsIntelMEI(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: BootGuard OTP fuses are not locked`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}
