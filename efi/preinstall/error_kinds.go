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

// ErrorKind describes an error detected during preinstall checks when
// using the [RunChecksContext] API.
type ErrorKind string

const (
	// ErrorKindNone indicates that no error occurred.
	ErrorKindNone ErrorKind = ""

	// ErrorKindInternal indicates that some kind of internal error occurred.
	ErrorKindInternal ErrorKind = "internal-error"

	// ErrorKindShutdownRequired indicates that a shutdown is required, and
	// is returned in response to some actions.
	ErrorKindShutdownRequired ErrorKind = "shutdown-required"

	// ErrorKindRebootRequired indicates that a reboot is required, and is
	// returned in response to some actions.
	ErrorKindRebootRequired ErrorKind = "reboot-required"

	// ErrorKindUnexpectedAction indicates that an action was supplied that
	// is unexpected because it isn't a remedial action associated with the
	// previously returned errors.
	ErrorKindUnexpectedAction ErrorKind = "unexpected-action"

	// ErrorKindMissingArgument is returned if an action was supplied
	// that requires one or more arguments, but not enough arguments
	// are supplied.
	ErrorKindMissingArgument ErrorKind = "missing-argument"

	// ErrorKindInvalidArgument is returned if an action was supplied
	// that requires one or more arguments, but one or more of the
	// supplied arguments are invalid.
	ErrorKindInvalidArgument ErrorKind = "invalid-argument"

	// ErrorKindActionFailed indicates that the supplied action did not
	// succeed for some reason.
	ErrorKindActionFailed ErrorKind = "action-failed"

	// ErrorKindTPMAuthFail indicates that the supplied action failed
	// because of a TPM authorization failure. If the authorization
	// failure was with the lockout hierarchy, this makes the lockout
	// hierarchy unavailable for the pre-programmed recovery period,
	// and any actions that depend on the lockout hierarchy will become
	// unavailable.
	ErrorKindTPMAuthFail ErrorKind = "tpm-auth-fail"

	// ErrorKindRunningInVM indicates that the current environment is a
	// virtal machine.
	ErrorKindRunningInVM ErrorKind = "running-in-vm"

	// ErrorKindNoSuitableTPM2Device indicates that the device has no
	// suitable TPM2 device. This is a fatal error. This error means that
	// full-disk encryption is not supported on this device.
	ErrorKindNoSuitableTPM2Device ErrorKind = "no-suitable-tpm2-device"

	// ErrorKindTPMDeviceDisabled indicates that there is a TPM device
	// but it is currently disabled. Note that after enabling it, it may
	// still fail further checks which mean it is unsuitable, resulting in
	// a ErrorKindNoSuitableTPM2Device error.
	ErrorKindTPMDeviceDisabled ErrorKind = "tpm-device-disabled"

	// ErrorKindTPMDeviceLockout indicates that the TPM's dictionary attack
	// logic is currently triggered, preventing the use of any DA protected
	// resources.
	ErrorKindTPMDeviceLockout ErrorKind = "tpm-device-lockout"

	// ErrorKindTPMHierarchyOwned indicates that a TPM hierarchy is currently
	// owned because it has an authorization value set. This will be supplied
	// with a single argument of the tpm2.Handle type to indicate which hierarchy
	// the error is referring to.
	ErrorKindTPMHierarchyOwned ErrorKind = "tpm-hierarchy-owned"

	// ErrorKindInsufficientTPMCounters indicates that there aren't sufficient
	// NV counters available to support FDE along with reprovisioning in the
	// future.
	ErrorKindInsufficientTPMCounters ErrorKind = "insufficient-tpm-counters"

	// ErrorKindNoSuitablePCRBank indicates that it was not possible to select
	// a suitable PCR bank.
	ErrorKindNoSuitablePCRBank ErrorKind = "no-suitable-pcr-bank"

	// ErrorKindTPMCommandError indicates that an error occurred whilst
	// communicating with the TPM device. If it is a TPM error response, it
	// will be accompanied with 2 arguments - the first one will be of the
	// type [tpm2.CommandCode], and the second one will be of the type
	// [tpm2.ResponseCode].
	ErrorKindTPMCommandError ErrorKind = "tpm-command-error"

	// ErrorKindFirmwareMeasurementError indicates an error in the way that the
	// platform firmware performs measurements. This will include one or more
	// instances of tpm2.Handle as arguments to indicate which PCRs failed.
	ErrorKindFirmwareMeasurementError ErrorKind = "firmware-measurement-error"

	// ErrorKindEmptyPCRBank indicates that a PCR bank is enabled but unused.
	// Whilst this isn't an issue for the FDE use case because we select a good
	// bank, it does break measured boot from this device, permitting an adversary
	// to spoof arbitrary trusted platforms by replaying PCR extends from software.
	// This will be accompanied with a single argument - the digest algorithm of the
	// empty bank of the type tpm2.HashAlgorithmId.
	ErrorKindEmptyPCRBank ErrorKind = "empty-pcr-bank"

	// ErrorKindTCGLog indicates that there was an error with the TCG log passed
	// from the firmware to the kernel, and exposed to userspace via sysfs. An
	// example error could mean that the log is invalid and unable to be decoded.
	ErrorKindTCGLog ErrorKind = "tcg-log"

	// ErrorKindUnexpectedTPMError indicates that an unexpected error occurred with
	// the TPM which isn't described by a more specific error message.
	ErrorKindUnexpectedTPMError ErrorKind = "unexpected-tpm-error"

	// ErrorKindNoKernelIOMMU indicates that the OS kernel was not built with DMA
	// remapping support, or some configuration has resulted in it being disabled.
	ErrorKindNoKernelIOMMU ErrorKind = "no-kernel-iommu"

	// ErrorKindPlatformFirmwareInsufficientProtection indicates that the platform firmware
	// lacks sufficient protection against tampering (ie, on Intel systems, Intel BootGuard
	// isn't configured correctly). This error makes it possible for an adversary to replace
	// the firmware with one that bypasses any OS level protections.
	ErrorKindPlatformFirmwareInsufficientProtection ErrorKind = "platform-firmware-insufficient-protection"

	// ErrorKindTPMStartupLocalityNotProtected indicates that the system has a discrete TPM
	// and the startup locality is not protected from access by privileged code running at
	// ring 0, such as the platform firmware or OS kernel. This makes it impossible to enable
	// a mitigation against reset attacks (see the description for DiscreteTPMDetected for more
	// information).
	ErrorKindTPMStartupLocalityNotProtected ErrorKind = "tpm-startup-locality-not-protected"

	// ErrorKindVARSuppliedDriversPresent indicates that drivers running from value-added-retailer
	// components were detected. Whilst these should generally be authenticated as part of the
	// secure boot chain and the digsts of the executed code measured to the TPM, the presence of
	// these does increase PCR fragility, and a user may choose not to trust this code (in which
	// case, they will need to disable it somehow).
	ErrorKindVARSuppliedDriversPresent ErrorKind = "var-supplied-drivers-present"

	// ErrorKindSysPrepApplicationsPresent indicates that system preparation applications were
	// detected to be running before the operating system. The OS does not use these and they
	// increase the fragility of PCR4 because they are beyond the control of the operating system.
	// In general, it is recommended that these are disabled.
	ErrorKindSysPrepApplicationsPresent ErrorKind = "sys-prep-applications-present"

	// ErrorKindAbsolutePresent indicates that Absolute was detected to be executing before the
	// initial OS loader. This is an endpoint management agent that is shipped with the platform
	// firmware. As it requires an OS component, it is generally recommended that this is disabled
	// via the firmware settings UI. Leaving it enabled does increase fragility of PCR4 because it
	// exposes it to changes via firmware updates.
	ErrorKindAbsolutePresent ErrorKind = "absolute-present"

	// ErrorKindInvalidSecureBootMode indicates that the secure boot mode is invalid. Either secure
	// boot is disabled or deployed mode is not enabled.
	ErrorKindInvalidSecureBootMode ErrorKind = "invalid-secure-boot-mode"

	// ErrorKindWeakSecureBootAlgorithmsDetected indicates that either pre-OS components were
	// authenticated with weak Authenticode digests, or CAs with weak public keys were used to
	// authenticate components. This check does have some limitations - for components other than
	// OS components, it is not possible to determine the properties of the signing key for signed
	// components - it is only possible to determine the properties of the trust anchor (the
	// certificate that is stored in db).
	ErrorKindWeakSecureBootAlgorithmsDetected ErrorKind = "weak-secure-boot-algorithms-detected"

	// ErrorKindPreOSDigestVerificationDetected indicates that pre-OS components were authenticated
	// by matching their Authenticode digest to an entry in db. This means that db has to change with
	// every firmware update, increasing the fragility of PCR7.
	ErrorKindPreOSDigestVerificationDetected ErrorKind = "pre-os-digest-verification-detected"
)
