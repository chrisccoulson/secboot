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
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/linux"
)

const (
	pcClientClass uint32 = 0x00000001
)

var (
	ErrNoPCClientTPM = errors.New("not a PC-Client TPM")
	ErrTPMIsDisabled = errors.New("TPM has been disabled by the firmware")
)

func newTPM2ResourceManagedContext() (*tpm2.TPMContext, error) {
	device, err := linux.DefaultTPM2Device()
	if err != nil {
		return nil, err
	}

	rmDevice, err := device.ResourceManagedDevice()
	switch {
	case err == linux.ErrNoResourceManagedDevice:
		return tpm2.OpenTPMDevice(device) // use the raw device. This can block, and might block other users
	case err != nil:
		return nil, err
	default:
		return tpm2.OpenTPMDevice(rmDevice) // use the resource managed device. This shouldn't block if nobody has the raw device open
	}
}

func checkTPM2DeviceClass(tpm *tpm2.TPMContext) error {
	// Check TPM2 device class. The class says a lot about the TPM such as
	// mandatory commands, algorithms, PCR banks and the minimum number of PCRs.
	// In all honesty, we're only ever likely to see PC-Client devices here because
	// that's basically all that exists, but check anyway just in case.
	val, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyPSFamilyIndicator)
	if err != nil {
		return fmt.Errorf("cannot obtain value for TPM_PT_PS_FAMILY_INDICATOR: %w", err)
	}
	if val != pcClientClass {
		return ErrNoPCClientTPM
	}
	return nil
}

func checkTPM2DeviceIsEnabled(tpm *tpm2.TPMContext) error {
	val, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyStartupClear)
	if err != nil {
		return fmt.Errorf("cannot obtain value for TPM_PT_STARTUP_CLEAR: %w", err)
	}

	sc := tpm2.StartupClearAttributes(val)
	if sc&(tpm2.AttrShEnable|tpm2.AttrEhEnable) != (tpm2.AttrShEnable | tpm2.AttrEhEnable) {
		return ErrTPMIsDisabled
	}
	return nil
}

func openAndCheckTPM2Device() (tpm *tpm2.TPMContext, err error) {
	// Check for and open TPM2 device
	tpm, err = newTPM2ResourceManagedContext()
	if err != nil {
		return nil, err
	}
	savedTpm := tpm
	defer func() {
		if err == nil {
			return
		}
		savedTpm.Close()
	}()

	if err := checkTPM2DeviceClass(tpm); err != nil {
		return nil, err
	}
	if err := checkTPM2DeviceIsEnabled(tpm); err != nil {
		return nil, err
	}

	return tpm, nil
}
