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

package preinstall

import (
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/ppi"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

var (
	obtainTPMDevicePPI = obtainTPMDevicePPIFallback
)

func obtainTPMDevicePPIFallback(dev tpm2.TPMDevice) (ppi.PPI, error) {
	return nil, errors.New("physical presence interface not supported")
}

func runPPIAction(env internal_efi.HostEnvironment, action Action) (ppi.StateTransitionAction, error) {
	dev, err := env.TPMDevice()
	if err != nil {
		return 0, err
	}
	p, err := obtainTPMDevicePPI(dev)
	if err != nil {
		return 0, fmt.Errorf("cannot obtain physical presence interface: %w", err)
	}
	if p == nil {
		return 0, ppi.ErrOperationUnsupported
	}

	switch action {
	case ActionEnableTPMViaFirmware:
		if err := p.EnableTPM(); err != nil {
			return 0, fmt.Errorf("cannot submit request to enable the TPM: %w", err)
		}
	case ActionEnableAndClearTPMViaFirmware:
		if err := p.EnableAndClearTPM(); err != nil {
			return 0, fmt.Errorf("cannot submit request to enable and clear the TPM: %w", err)
		}
	case ActionClearTPMViaFirmware:
		if err := p.ClearTPM(); err != nil {
			return 0, fmt.Errorf("cannot submit request to clear the TPM: %w", err)
		}
	default:
		return 0, fmt.Errorf("invalid PPI action %q", action)
	}

	sta, err := p.StateTransitionAction()
	if err != nil {
		return 0, fmt.Errorf("cannot obtain action required to transition to pre-OS environment: %w", err)
	}
	switch sta {
	case ppi.StateTransitionShutdownRequired:
		// ok
	case ppi.StateTransitionRebootRequired:
		// ok
	default:
		return 0, fmt.Errorf("unsupported state transition action %v", sta)
	}
	return sta, nil
}

func isPPIActionAvailable(env internal_efi.HostEnvironment, action Action) (bool, error) {
	dev, err := env.TPMDevice()
	if err != nil {
		return false, err
	}
	p, err := obtainTPMDevicePPI(dev)
	if err != nil {
		return false, fmt.Errorf("cannot obtain physical presence interface: %w", err)
	}
	if p == nil {
		return false, nil
	}

	var operation ppi.OperationId
	switch action {
	case ActionEnableTPMViaFirmware:
		operation = ppi.OperationEnableTPM
	case ActionEnableAndClearTPMViaFirmware:
		operation = ppi.OperationEnableAndClearTPM
	case ActionClearTPMViaFirmware:
		operation = ppi.OperationClearTPM
	default:
		return false, errors.New("invalid PPI action")
	}

	status, err := p.OperationStatus(operation)
	if err != nil {
		return false, fmt.Errorf("cannot obtain operation status for action: %w", err)
	}
	switch status {
	case ppi.OperationPPRequired, ppi.OperationPPNotRequired:
		return true, nil
	default:
		return false, nil
	}
}
