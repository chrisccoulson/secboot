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
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/intel-go/cpuid"
)

const (
	ia32DebugInterface = 0xc80

	ia32DebugEnable uint64 = 1 << 0
	ia32DebugLock   uint64 = 1 << 30
)

var (
	iommuDir = "/sys/class/iommu"
	msrFile  = "/dev/cpu/0/msr"
)

func checkForIOMMU() error {
	f, err := os.Open(iommuDir)
	switch {
	case os.IsNotExist(err):
		return ErrNoIOMMUSupport
	case err != nil:
		return err
	}
	defer f.Close()

	entries, err := f.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		fi, err := os.Stat(filepath.Join(f.Name(), entry.Name()))
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("expected only directories in %s", iommuDir)
		}
		tgt, err := filepath.EvalSymlinks(filepath.Join(f.Name(), entry.Name(), "subsystem"))
		if err != nil {
			return fmt.Errorf("cannot resolve subsystem symlink: %w", err)
		}
		if filepath.Base(tgt) == "iommu" {
			// The kernel says we have an IOMMU
			return nil
		}
	}

	return ErrNoIOMMUSupport
}

func checkCPUDebuggingConfigMSR() error {
	// Check for "Silicon Debug Interface", returned in bit 11 of %ecx when calling
	// cpuid with %eax=1.
	debugSupported := cpuid.HasFeature(cpuid.SDBG)
	if !debugSupported {
		return nil
	}

	f, err := os.Open(msrFile)
	switch {
	case os.IsNotExist(err):
		return errors.New("missing kernel MSR support")
	case err != nil:
		return err
	}
	defer f.Close()

	var data [8]byte
	if _, err := f.ReadAt(data[:], ia32DebugInterface); err != nil {
		return fmt.Errorf("cannot read from MSR device: %w", err)
	}

	debugVal := binary.LittleEndian.Uint64(data[:])
	if debugVal&ia32DebugEnable > 0 {
		return ErrCPUDebugEnabledOrAvailable
	}
	if debugVal&ia32DebugLock == 0 {
		return ErrCPUDebugEnabledOrAvailable
	}

	return nil
}

type cpuVendor int

const (
	cpuVendorUnknown cpuVendor = iota
	cpuVendorIntel
	cpuVendorAMD
)

func determineCPUVendor() (cpuVendor, error) {
	switch cpuid.VendorIdentificatorString {
	case "GenuineIntel":
		return cpuVendorIntel, nil
	case "AuthenticAMD":
		return cpuVendorAMD, nil
	default:
		return cpuVendorUnknown, fmt.Errorf("unknown CPU vendor: %s", cpuid.VendorIdentificatorString)
	}
}

func checkPlatformFirmwareProtections() error {
	cpuVendor, err := determineCPUVendor()
	if err != nil {
		return fmt.Errorf("cannot determine CPU vendor: %w", err)
	}

	switch cpuVendor {
	case cpuVendorIntel:
		if err := checkPlatformFirmwareProtectionsIntelMEI(); err != nil {
			return fmt.Errorf("encountered an error when determining platform firmware protections using Intel MEI: %w", err)
		}
	case cpuVendorAMD:
		return errors.New("TODO: checking platform firmware protections is not yet implemented for AMD")
	default:
		panic("not reached")
	}

	if err := checkCPUDebuggingConfigMSR(); err != nil {
		return fmt.Errorf("encountered an error when determining CPU debugging configuration from MSRs: %w", err)
	}

	if err = checkForIOMMU(); err != nil {
		return fmt.Errorf("encountered an error whilst checking sysfs for IOMMU support: %w", err)
	}

	// TODO: Maybe check for pre-boot DMA protection

	return nil
}
