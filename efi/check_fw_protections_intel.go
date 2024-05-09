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

	meOperationMode    uint8
	errorEnforcePolicy uint8
)

func (reg hfsts1) operationMode() meOperationMode {
	return meOperationMode(reg & hfsts1OperationMode >> 16)
}

func (reg hfsts6) errorEnforcePolicy() errorEnforcePolicy {
	return errorEnforcePolicy(reg & hfsts6ErrorEnforcePolicy >> 6)
}

const (
	hfsts1MfgMode       hfsts1 = 1 << 4
	hfsts1OperationMode hfsts1 = 0xf0000

	hfsts6ForceBootGuardACM  hfsts6 = 1 << 0
	hfsts6CpuDebugDisable    hfsts6 = 1 << 1
	hfsts6ErrorEnforcePolicy hfsts6 = 0xc0
	hfsts6MeasuredBoot       hfsts6 = 1 << 8
	hfsts6VerifiedBoot       hfsts6 = 1 << 9
	hfsts6BootGuardDisable   hfsts6 = 1 << 28
	hfsts6FPFSOCLock         hfsts6 = 1 << 30

	meOperationModeNormal         meOperationMode = 0
	meOperationModeDebug          meOperationMode = 2
	meOperationModeDisabled       meOperationMode = 3
	meOperationModeOverrideJumper meOperationMode = 4
	meOperationModeOverrideMei    meOperationMode = 5
	meOperationModeMaybeSps       meOperationMode = 7

	errorEnforcePolicyNothing        errorEnforcePolicy = 0
	errorEnforcePolicyShutdownTo     errorEnforcePolicy = 1
	errorEnforcePolicyShutdownNow    errorEnforcePolicy = 2
	errorEnforcePolicyShutdown30Mins errorEnforcePolicy = 3
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

func checkPlatformFirmwareProtectionsIntelMEI() (result firmwareProtectionResultFlags, err error) {
	if _, err := os.Stat(intelMEIDir); err != nil {
		return 0, errors.New("no MEI device exposed in sysfs")
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
		return 0, fmt.Errorf("cannot read HFSTS registers from sysfs: %w", err)
	}

	vers, err := readIntelMEVersionFromMEISysfs()
	if err != nil {
		return 0, fmt.Errorf("cannot obtain ME version from sysfs: %w", err)
	}

	// From here, these checks are based on the HSI checks performed in the pci-mei
	// plugin in fwupd.
	family := calculateIntelMEFamily(vers, hfsts1Reg)
	if err != nil {
		return 0, fmt.Errorf("cannot determine ME family: %w", err)
	}

	// Check manufacturing mode is not enabled.
	if hfsts1Reg&hfsts1MfgMode > 0 {
		return 0, errors.New("ME is in manufacturing mode: no firmware protections are enabled")
	}

	// Check operation mode
	switch hfsts1Reg.operationMode() {
	case meOperationModeOverrideJumper:
		return 0, errors.New("invalid ME operation mode: checks for software tampering may be disabled")
	default:
		// ok
	}

	if hfsts6Reg&hfsts6CpuDebugDisable == 0 {
		return 0, errors.New("ME indicates that CPU debug is not disabled")
	}

	// Check BootGuard configuration - BootGuard must be enabled. As it's an ACM, it's signed
	// by Intel and authenticated by a key that's rooted in the CPU microcode (which itself is
	// authenticated), it's essentially part of the TCB and the hardware root of trust. It must
	// have an appropriate error enforcement policy if it fails to execute, and the FPFs that
	// control it must be locked. BootGuard must at least be configured in measured boot mode,
	// where it performs the initial measurements of the platform firmware before it's executed,
	// for the platform to meet the requirements for FDE. Ideally it is configured also in
	// verified boot mode where the OEM programs the hash of their public key into the appropriate
	// FPFs in the ME and BootGuard uses this to authenticate the IBB of the firmware and refuses
	// to execute anything without a valid signature.

	// Check we have an appropriate ME family.
	switch family {
	case meFamilyUnknown:
		return 0, errors.New("BootGuard unsupported on unknown ME family")
	case meFamilyTxe:
		return 0, errors.New("BootGuard unsupported on TXE ME family")
	}

	// Ensure that BootGuard is mandatory.
	if hfsts6Reg&hfsts6BootGuardDisable > 0 {
		return 0, errors.New("BootGuard is disabled")
	}
	if hfsts6Reg&hfsts6ForceBootGuardACM == 0 {
		return 0, errors.New("BootGuard ACM is not forced")
	}

	// Check that an appropriate error enforcement policy is set.
	switch hfsts6Reg.errorEnforcePolicy() {
	case errorEnforcePolicyShutdownNow:
		// this is the ideal configuration
	case errorEnforcePolicyShutdown30Mins:
		// this is ok - some devices set this, and this is sufficient
		// for HSI-3 as well
	default:
		// no other policy is acceptable
		return 0, errors.New("invalid BootGuard enforcement policy")
	}

	// Make sure that the FPFs are locked.
	if hfsts6Reg&hfsts6FPFSOCLock == 0 {
		return 0, errors.New("BootGuard OTP fuses are not locked")
	}

	// Check the BootGuard mode
	if hfsts6Reg&hfsts6VerifiedBoot > 0 {
		// Awesome, verified boot is enabled
		return 0, nil
	}
	if hfsts6Reg&hfsts6MeasuredBoot == 0 {
		// Both verified boot and measured boot modes are disabled. This
		// platform is not suitable for FDE as it's trivial to replace
		// the firmware without any evidence of this.
		return 0, errors.New("BootGuard is configured with both measured boot and verified boot disabled")
	}

	// Proceed with measured boot mode only.
	return firmwareProtectionMeasuredBootMode, nil
}
