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

package efi

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var (
	intelMEIDir = "/sys/class/mei/mei0"
)

type (
	hfsts1 uint32
	hfsts2 uint32
	hfsts3 uint32
	hfsts4 uint32
	hfsts5 uint32
	hfsts6 uint32

	meOperationMode        uint8
	errorEnforcementPolicy uint8
)

func (reg hfsts1) operationMode() meOperationMode {
	return meOperationMode(reg & hfsts1OperationMode >> 16)
}

func (reg hfsts6) errorEnforcementPolicy() errorEnforcementPolicy {
	return errorEnforcementPolicy(reg & hfsts6ErrorEnforcementPolicy >> 6)
}

const (
	hfsts1MfgMode       hfsts1 = 1 << 4
	hfsts1OperationMode hfsts1 = 0xf0000

	hfsts6ForceBootGuardACM      hfsts6 = 1 << 0
	hfsts6ProtectBIOSEnv         hfsts6 = 1 << 3
	hfsts6ErrorEnforcementPolicy hfsts6 = 0xc0
	hfsts6MeasuredBoot           hfsts6 = 1 << 8
	hfsts6VerifiedBoot           hfsts6 = 1 << 9
	hfsts6BootGuardDisable       hfsts6 = 1 << 28
	hfsts6FPFSOCLock             hfsts6 = 1 << 30

	meOperationModeNormal         meOperationMode = 0
	meOperationModeDebug          meOperationMode = 2
	meOperationModeDisabled       meOperationMode = 3
	meOperationModeOverrideJumper meOperationMode = 4
	meOperationModeOverrideMei    meOperationMode = 5
	meOperationModeMaybeSps       meOperationMode = 7

	errorEnforcePolicyNothing        errorEnforcementPolicy = 0
	errorEnforcePolicyShutdown30Mins errorEnforcementPolicy = 1
	errorEnforcePolicyShutdownNow    errorEnforcementPolicy = 3
)

type meFamily uint8

const (
	meFamilyUnknown meFamily = iota
	meFamilySps
	meFamilyTxe
	meFamilyMe
	meFamilyCsme
)

func readIntelHFSTSRegistersFromMEISysfs(regs [6]*uint32) error {
	f, err := os.Open(filepath.Join(intelMEIDir, "fw_status"))
	if err != nil {
		return err
	}
	defer f.Close()

	i := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if i > len(regs)-1 {
			return errors.New("invalid fw_status format: too many entries")
		}

		str := scanner.Text()
		if len(str) != 8 {
			return fmt.Errorf("invalid fw_status format: unexpected line length for line %d (%d chars)", i, len(str))
		}

		n, err := fmt.Sscanf(str, "%08x", regs[i])
		if err != nil {
			return fmt.Errorf("invalid fw_status format: cannot scan line %d: %w", i, err)
		}
		if n != 1 {
			return fmt.Errorf("invalid fw_status format: unexpected number of arguments scanned for line %d", i)
		}

		i += 1
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error when scanning fw_status: %w", err)
	}
	if i != 6 {
		return errors.New("invalid fw_status format: not enough entries")
	}

	return nil
}

type meVersion struct {
	platform uint8
	major    uint8
	minor    uint8
	hotfix   uint8
	buildno  uint16
}

func decodeMeVersion(str string) (out meVersion, err error) {
	n, err := fmt.Sscanf(str, "%d:%d.%d.%d.%d", &out.platform, &out.major, &out.minor, &out.hotfix, &out.buildno)
	if err != nil {
		return meVersion{}, err
	}
	if n != 5 {
		return meVersion{}, errors.New("unexpected number of arguments scanned")
	}
	return out, nil
}

func (v meVersion) String() string {
	return fmt.Sprintf("%d:%d.%d.%d.%d", v.platform, v.major, v.minor, v.hotfix, v.buildno)
}

func readIntelMEVersionFromMEISysfs() (meVersion, error) {
	f, err := os.Open(filepath.Join(intelMEIDir, "fw_ver"))
	if err != nil {
		return meVersion{}, err
	}
	defer f.Close()

	var vers meVersion
	scanner := bufio.NewScanner(f)
	// Only care about the first line
	if scanner.Scan() {
		vers, err = decodeMeVersion(scanner.Text())
		if err != nil {
			return meVersion{}, fmt.Errorf("invalid fw_ver: %w", err)
		}
	} else {
		return meVersion{}, errors.New("invalid fw_ver: nothing to scan")
	}

	if err := scanner.Err(); err != nil {
		return meVersion{}, fmt.Errorf("error when scanning fw_ver: %w", err)
	}

	return vers, nil
}

func calculateIntelMEFamily(vers meVersion, hfsts1Reg hfsts1) meFamily {
	switch vers.major {
	case 0:
		return meFamilyUnknown
	case 1, 2:
		if hfsts1Reg.operationMode() == 0xf {
			return meFamilySps
		}
		return meFamilyTxe
	case 3, 4, 5:
		return meFamilyTxe
	case 6, 7, 8, 9, 10:
		return meFamilyMe
	default:
		return meFamilyCsme
	}
}

func checkPlatformFirmwareProtectionsIntelMEI() error {
	if _, err := os.Stat(intelMEIDir); err != nil {
		return errors.New("no MEI device exposed in sysfs")
	}

	var (
		// Host Firmware Status Registers provided by the ME. The meaning of the
		// bits of these registers is not described in the datasheet for the PCH.
		// Thankfully, others have done most of the leg work here to figure out
		// what most bits mean, and we're only interested in a few of them anyway.
		hfsts1Reg hfsts1
		hfsts2Reg hfsts2
		hfsts3Reg hfsts3
		hfsts4Reg hfsts4
		hfsts5Reg hfsts5
		hfsts6Reg hfsts6
	)

	if err := readIntelHFSTSRegistersFromMEISysfs([6]*uint32{
		(*uint32)(&hfsts1Reg),
		(*uint32)(&hfsts2Reg),
		(*uint32)(&hfsts3Reg),
		(*uint32)(&hfsts4Reg),
		(*uint32)(&hfsts5Reg),
		(*uint32)(&hfsts6Reg),
	}); err != nil {
		return fmt.Errorf("cannot read HFSTS registers from sysfs: %w", err)
	}

	vers, err := readIntelMEVersionFromMEISysfs()
	if err != nil {
		return fmt.Errorf("cannot obtain ME version from sysfs: %w", err)
	}

	// From here, these checks are based on the HSI checks performed in the pci-mei
	// plugin in fwupd.
	family := calculateIntelMEFamily(vers, hfsts1Reg)
	if err != nil {
		return fmt.Errorf("cannot determine ME family: %w", err)
	}

	// Check manufacturing mode is not enabled.
	if hfsts1Reg&hfsts1MfgMode > 0 {
		return &NoHCRTMError{errors.New("ME is in manufacturing mode: no firmware protections are enabled")}
	}

	// Check operation mode
	switch hfsts1Reg.operationMode() {
	case meOperationModeOverrideJumper:
		return &NoHCRTMError{errors.New("invalid ME operation mode: checks for software tampering may be disabled")}
	default:
		// ok
	}

	// Check BootGuard profile - BootGuard must be force enabled. As it's an ACM, it's signed
	// by Intel and authenticated by a key that's rooted in the CPU microcode (which itself is
	// authenticated), it's essentially part of the TCB and the hardware root of trust. It
	// must be configured at least in verified boot mode (where it verifies that the IBB has a
	// valid OEM supplied signature before allowing it to execute it), with measured boot mode
	// optional. Note that measured boot mode without verified boot mode is not a valid
	// configuration. It must have an appropriate error enforcement policy if it fails to execute.
	// The "Protect BIOS Environment" feauture muse be enabled. The FPFs that control the profile
	// and contain the hash of the OEM key must be locked.

	// First check we have an appropriate ME family.
	switch family {
	case meFamilyUnknown:
		return &NoHCRTMError{errors.New("BootGuard unsupported on unknown ME family")}
	case meFamilyTxe:
		return &NoHCRTMError{errors.New("BootGuard unsupported on TXE ME family")}
	}

	if hfsts6Reg&hfsts6BootGuardDisable > 0 {
		// This isn't a good start
		return &NoHCRTMError{errors.New("BootGuard is disabled")}
	}

	// Verify the full BootGuard profile.
	if hfsts6Reg&hfsts6ForceBootGuardACM == 0 {
		return &NoHCRTMError{errors.New("the BootGuard ACM is not forced to execute - the CPU can execute arbitrary code from the legacy reset vector if BootGuard cannot be successfully loaded")}
	}
	if hfsts6Reg&hfsts6VerifiedBoot == 0 {
		return &NoHCRTMError{errors.New("BootGuard verified boot mode is not enabled - this allows arbitrary firmware that doesn't have a valid signature to be executed")}
	}
	if hfsts6Reg.errorEnforcementPolicy() != errorEnforcePolicyShutdownNow {
		return &NoHCRTMError{errors.New("BootGuard does not have an appropriate error enforcement policy")}
	}
	if hfsts6Reg&hfsts6ProtectBIOSEnv == 0 {
		return &NoHCRTMError{errors.New("the \"Protect BIOS Environment\" feature is not enabled")}
	}

	// Make sure that the FPFs are locked.
	if hfsts6Reg&hfsts6FPFSOCLock == 0 {
		return &NoHCRTMError{errors.New("BootGuard OTP fuses are not locked")}
	}

	// Everything is ok
	return nil
}
