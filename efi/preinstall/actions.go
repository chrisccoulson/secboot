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

// Action describes an Action to resolve a detected error. Some [ErrorKind]s may
// be associated with one or more Actions that can be taken in order to resolve
// the error. The code that calls [RunChecksContext.Run] can respond with one of
// these actions.
//
// An installer UI may offer some of these actions in response to detected errors,
// although note that it doesn't have to offer all actions associated with an error,
// and the documentation for some actions provide hints as to whether they are
// inappropriate for an installer UI.
type Action string

const (
	// ActionNone corresponds to no action.
	ActionNone Action = ""

	// ActionReboot corresponds to rebooting the device. Note that this action
	// is only a hint that a reboot is a suitable action. It is not accepted by
	// RunChecksContext.Run - it is up to the calling code to perform the reboot.
	ActionReboot Action = "reboot"

	// ActionShutdown corresponds to shutting down the device. Note that this
	// action is only a hint that a shutdown is a suitable action. It is not
	// accepted by RunChecksContext.Run - it is up to the calling code to perform
	// the shutdown.
	ActionShutdown Action = "shutdown"

	// ActionRebootToFWSettings corresponds to rebooting the device to the firmware
	// settings in order to resolve a problem manually.  Note that this action
	// is only a hint that a reboot to firmware settings is a suitable action. It
	// is not accepted by RunChecksContext.Run - it is up to the calling code to
	// perform the reboot.
	ActionRebootToFWSettings Action = "reboot-to-fw-settings"

	// ActionContactOEM is a hint that contacting the OEM for the device is a valid
	// action. This action cannot be performed by this package - it exists as a hint
	// only.
	ActionContactOEM Action = "contact-oem"

	// ActionContactOSVendor is a hint that contacting the OS vendor is a valid action.
	// This action cannot be performed by this package - it exists as a hint only.
	ActionContactOSVendor Action = "contact-os-vendor"

	// ActionPermitVM tells RunChecksContext.Run to permit the checks to pass
	// despite running in a virtual machine. See the documentation for
	// PermitVirtualMachine for the pitfalls of this. This action causes the
	// firmware protection tests to be skipped.
	ActionPermitVM Action = "permit-vm"

	// ActionEnableTPMViaFirmware tells RunChecksContext.Run to enable the TPM
	// via the physical presence interface. If successful, this action will
	// respond with ErrorKindShutdown or ErrorKindReboot.
	ActionEnableTPMViaFirmware Action = "enable-tpm-via-firmware"

	// ActionEnableAndClearTPMViaFirmware tells RunChecksContext.Run to enable
	// and clear the TPM via the physical presence interface. If successful, this
	// action will respond with ErrorKindShutdown or ErrorKindReboot.
	ActionEnableAndClearTPMViaFirmware Action = "enable-and-clear-tpm-via-firmware"

	// ActionClearTPMViaFirmware tells RunChecksContext.Run to clear the TPM
	// via the physical presence interface. If successful, this action will
	// respond with ErrorKindShutdown or ErrorKindReboot.
	ActionClearTPMViaFirmware Action = "clear-tpm-via-firmware"

	// ActionClearTPM tells RunChecksContext.Run to clear the TPM using the lockout
	// hierarchy. The caller must supply a valid authorization value for the lockout
	// hierarchy in the form of a []byte type.
	//
	// If this fails with ErrorKindTPMAuthFail then the lockout hierarchy becomes
	// unavailabe for the pre-programmed recovery period. This means that this action
	// and any others that depend on the lockout hierarchy become unavailable.
	//
	// This action is considered an expert action because it requires the user to
	// supply an auth value which could either be a passphrase or a digest,
	// potentially making it inappropriate to offer in a graphical UI.
	ActionClearTPM Action = "clear-tpm"

	// ActionTPMDALockoutReset tells RunChecksContext.Run to reset the TPM's dictionary
	// attack counter if the TPM is in lockout mode. The caller must supply a valid
	// authorization value for the lockout hierarchy in the form of a []byte type.
	//
	// If this fails with ErrorKindTPMAuthFail then the lockout hierarchy becomes
	// unavailabe for the pre-programmed recovery period. This means that this action
	// and any others that depend on the lockout hierarchy become unavailable.
	//
	// This action is considered an expert action because it requires the user to
	// supply an auth value which could either be a passphrase or a digest,
	// potentially making it inappropriate to offer in a graphical UI.
	ActionTPMDALockoutReset Action = "tpm-da-lockout-reset"

	// ActionClearTPMHierarchyOwnership tells RunChecksContext.Run to clear the ownership
	// of a hierarchy. The caller must supply 2 arguments - the tpm2.Handle for the
	// relevant hierarchy, and the current authorization value in the form of a []byte
	// type. If this is used to clear the ownership of the lockout hierarchy, and it
	// fails with ErrorKindTPMAuthFail, then the lockout hierarchy becomes unavailable.
	// Actions that depend on it will become unavailable.
	//
	// This action is considered an expert action because it requires the user to
	// supply an auth value which could either be a passphrase or a digest,
	// potentially making it inappropriate to offer in a graphical UI.
	ActionClearTPMHierarchyOwnership Action = "clear-tpm-hierarchy-ownership"

	// ActionPermitNoDiscreteTPMResetMitigation tells RunChecksContext.Run to pass
	// despite not being able to enable a limited reset attack mitigations. See the
	// description of the DiscreteTPMDetected flag for more details.
	ActionPermitNoDiscreteTPMResetMitigation Action = "permit-no-discrete-tpm-reset-mitigation"

	// ActionPermitEmptyPCRBanks tells RunChecksContext.Run to pass even if there
	// are empty PCR banks. Whilst this is ok for FDE, it breaks remote attestation
	// because it permits an adversary to replay and attest an entire host state
	// from software.
	ActionPermitEmptyPCRBanks Action = "permit-empty-pcr-banks"

	// ActionPermitVARSuppliedDrivers tells RunChecksContext.Run to pass even if
	// there are value-added-retailer devices that supply firmware that is not
	// provided directly by the platform manufacturer.
	ActionPermitVARSuppliedDrivers Action = "permit-var-supplied-drivers"

	// ActionPermitSysPrepApplications tells RunChecksContext.Run to pass even
	// if there are system preparation applications running before the operating
	// system. In general, these should be disabled first.
	// TODO: Add an action to disable these by erasing the corresponding SysPrepOrder
	// and SysPrepXXXX variable entries.
	ActionPermitSysPrepApplications Action = "permit-sysprep-applications"

	// ActionPermitAbsolute tells RunChecksContext.Run to pass even if Absolute is
	// detected to be running before the operating system. In general, it is better for
	// this to be disabled first if the firmware settings UI provides a way to do this.
	// TODO: Add an action to disable this automatically on supported devices, such as
	// Dell devices, which allow this to be disabled from userspace.
	ActionPermitAbsolute Action = "permit-absolute"

	// ActionPermitNoSecureBoot tells RunChecksContext.Run to pass even if secure boot
	// isn't configured properly, as long as it is possible to produce a PCR profile that
	// is secure in the absence of secure boot.
	ActionPermitNoSecureBoot Action = "permit-no-secure-boot"

	// ActionPermitWeakSecureBootAlgorithms tells RunChecksContext.Run to pass even if
	// weak algorithms are used during secure boot verification.
	ActionPermitWeakSecureBootAlgorithms Action = "permit-weak-secure-boot-algorithms"

	// ActionPermitOSDigestVerification tells RunChecksContext.Run to pass even if pre-OS
	// components are authenticated by matching their Authenticode digest to an entry in db
	// as opposed to relying on the component being signed. This generally increases the
	// fragility of PCR7 because it means that it needs to be updated with everywhere
	// firmware update.
	ActionPermitPreOSDigestVerification Action = "permit-pre-os-digest-verification"
)
