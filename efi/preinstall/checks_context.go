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
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/ppi"
	secboot_efi "github.com/snapcore/secboot/efi"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

var errorKindToActions map[ErrorKind][]Action

func init() {
	errorKindToActions = map[ErrorKind][]Action{
		ErrorKindShutdownRequired: []Action{
			ActionShutdown,
		},
		ErrorKindRebootRequired: []Action{
			ActionReboot,
		},
		ErrorKindRunningInVM: []Action{
			ActionPermitVM, // offer the option of running inside the VM, bypassing the platform firmware protections
		},
		ErrorKindTPMDeviceDisabled: []Action{
			ActionRebootToFWSettings,           // suggest rebooting to the firmware settings UI to enable the TPM
			ActionEnableTPMViaFirmware,         // suggest enabling the TPM via the PPI
			ActionEnableAndClearTPMViaFirmware, // suggest enabling and clearing the TPM via the PPI
		},
		ErrorKindTPMDeviceLockout: []Action{
			ActionRebootToFWSettings,  // suggest rebooting to the firmware settings UI to clear the TPM
			ActionClearTPMViaFirmware, // suggest clearing the TPM via the PPI
			ActionClearTPM,            // suggest clearing the TPM using the TPM2_Clear command, if the lockout hierarchy authorization value is known
			ActionTPMDALockoutReset,   // suggest resetting the DA lockout using the TPM2_DictionaryAttackLockReset command, if the lockout hierarchy authorization value is known
		},
		ErrorKindTPMHierarchyOwned: []Action{
			ActionRebootToFWSettings,         // suggest rebooting to the firmware settings UI to clear the TPM
			ActionClearTPMViaFirmware,        // suggest clearing the TPM via the PPI
			ActionClearTPM,                   // suggest clearing the TPM using the TPM2_Clear command, if the lockout hierarchy authorization value is known
			ActionClearTPMHierarchyOwnership, // suggest clearing the authorization value using the TPM2_HierarchyChangeAuth command, if the existing authorization value is known
		},
		ErrorKindInsufficientTPMCounters: []Action{
			ActionRebootToFWSettings,  // suggest rebooting to the firmware settings UI to clear the TPM
			ActionClearTPMViaFirmware, // suggest clearing the TPM via the PPI
			ActionClearTPM,            // suggest clearing the TPM using the TPM2_Clear command, if the lockout hierarchy authorization value is known
		},
		ErrorKindNoSuitablePCRBank: []Action{
			ActionRebootToFWSettings, // suggest rebooting to the firmware settings UI to enable other PCR banks
			// TODO: Add an action to reconfigure PCR banks via the PPI if the error is because of a missing bank
		},
		ErrorKindEmptyPCRBank: []Action{
			ActionRebootToFWSettings,  // suggest rebooting to the firmware settings UI to disable the empty PCR bank
			ActionPermitEmptyPCRBanks, // permit the empty PCR bank, as this is ok for FDE.
			// TODO: Add an action to reconfigure PCR banks via the PPI if the error is because of a missing bank
		},
		ErrorKindFirmwareMeasurementError: []Action{
			ActionContactOEM, // suggest contacting the OEM because of a firmware bug
		},
		ErrorKindTCGLog: []Action{
			ActionContactOEM, // suggest contacting the OEM because of a firmware bug
		},
		ErrorKindTPMStartupLocalityNotProtected: []Action{
			ActionPermitNoDiscreteTPMResetMitigation, // suggest proceeding without the discrete TPM reset mitigation, given its limitations
		},
		ErrorKindNoKernelIOMMU: []Action{
			ActionContactOSVendor, // suggest contacting the OS vendor to supply a kernel with this feature enabled.
		},
		ErrorKindPlatformFirmwareInsufficientProtection: []Action{
			ActionContactOEM, // suggest contacting the OEM because the platform firmware protections are not configured correctly.
		},
		ErrorKindVARSuppliedDriversPresent: []Action{
			ActionPermitVARSuppliedDrivers, // permit the execution of value-added-retailer drivers from devices that is shipped separately from the platform firmware
		},
		ErrorKindSysPrepApplicationsPresent: []Action{
			ActionPermitSysPrepApplications, // permit the execution of system preparation applications before the OS. This is generally not a good idea.
			// TODO: Add an action to just disable these by erasing the
			//  SysPrepOrder and SysPrepXXXX variables
		},
		ErrorKindAbsolutePresent: []Action{
			ActionPermitAbsolute, // permit the execution of the Absolute firmware component. It is generally recommended to disable this first.
			// TODO: Add an action to just disable this automatically on supported platforms (eg, Dell via the WMI interface)
		},
		ErrorKindInvalidSecureBootMode: []Action{
			ActionRebootToFWSettings, // suggest rebooting to the firmware settings UI to properly configure secure boot
			ActionPermitNoSecureBoot, // permit continuing without secure boot, as long as a secure PCR policy can still be created without it.
		},
		ErrorKindWeakSecureBootAlgorithmsDetected: []Action{
			ActionPermitWeakSecureBootAlgorithms, // permit including secure boot policy even though weak algorithms were used during verification
		},
		ErrorKindPreOSDigestVerificationDetected: []Action{
			ActionPermitPreOSDigestVerification, // permit including secure boot policy even though some pre-OS components are unsigned and verified by matching them to digests in db.
		},
	}
}

// ErrorKindAndActions describes an error and a set of potential remedial actions.
type ErrorKindAndActions struct {
	ErrorKind ErrorKind       `json:"kind"`    // The error kind
	ErrorArgs json.RawMessage `json:"args"`    // The arguments associated with the error. See the documentation for the ErrorKind for the meaning of these.
	Error     error           `json:"-"`       // The original error. This is not serialized to JSON.
	Actions   []Action        `json:"actions"` // Potential remedial actions. This may be empty. Note that not all actions can be supplied to RunChecksContext.Run.
}

// singleErrorKindAndActions turns a single error kind, its arguments and actions into a slice of error kinds,
// as this is what is returned from [RunChecksContext.Run].
func singleErrorKindAndActions(kind ErrorKind, args []any, err error, actions ...Action) []*ErrorKindAndActions {
	jsonArgs, jsonErr := json.Marshal(args)
	if jsonErr != nil {
		return singleErrorKindAndActions(ErrorKindInternal, nil, err)
	}
	return []*ErrorKindAndActions{{ErrorKind: kind, ErrorArgs: jsonArgs, Error: err, Actions: actions}}
}

// unpackRunChecksErrors unpacks a [RunChecksErrors], as [RunChecks]
// may return multiple errors in a single invocation.
func unpackRunChecksErrors(err error) []error {
	var rce *RunChecksErrors
	if errors.As(err, &rce) {
		return rce.Errs
	}
	return []error{err}
}

// RunChecksContext maintains context for multiple invocations of [RunChecks] to permit the
// install process to iterate and resolve detected issues where possible. It also reduces
// the burden of selecting an initial set of [CheckFlags].
type RunChecksContext struct {
	env          internal_efi.HostEnvironment
	flags        CheckFlags
	loadedImages []secboot_efi.Image
	profileOpts  PCRProfileOptionsFlags

	errs    []error
	lastErr error
	result  *CheckResult

	availableActions map[Action]bool
	expectedActions  []Action
}

// NewRunChecksContext returns a new RunChecksContext instance with the initial flags for [RunChecks]
// and the supplied list of boot components for the current boot. The supplied [PCRProfileOptionsFlags]
// represent the preferred [WithAutoTCGPCRProfile] - the PCRs that are determined to be required to
// build the profile will be made mandatory automatically by passing the relevant flags to [RunChecks].
// There is no need for the caller to supply any of these *SupportRequired flags as the initial flags,
// and this may have the effect of limiting the number of devices which pass the checks.
func NewRunChecksContext(initialFlags CheckFlags, loadedImages []secboot_efi.Image, profileOpts PCRProfileOptionsFlags) *RunChecksContext {
	return &RunChecksContext{
		env:          runChecksEnv,
		flags:        initialFlags,
		loadedImages: loadedImages,
		profileOpts:  profileOpts,
		availableActions: map[Action]bool{
			ActionNone:                               true,
			ActionReboot:                             true,
			ActionShutdown:                           true,
			ActionRebootToFWSettings:                 true,
			ActionContactOEM:                         true,
			ActionContactOSVendor:                    true,
			ActionPermitVM:                           true,
			ActionTPMDALockoutReset:                  true, // Assume this is available until we find out for sure that the lockout hierarchy is unavailable
			ActionClearTPMHierarchyOwnership:         true,
			ActionPermitNoDiscreteTPMResetMitigation: true,
			ActionPermitEmptyPCRBanks:                true,
			ActionPermitVARSuppliedDrivers:           true,
			ActionPermitSysPrepApplications:          true,
			ActionPermitAbsolute:                     true,
			ActionPermitWeakSecureBootAlgorithms:     true,
			ActionPermitPreOSDigestVerification:      true,
		},
	}
}

func (c *RunChecksContext) markLockoutHierarchyUnavailable() {
	c.availableActions[ActionClearTPM] = false
	c.availableActions[ActionTPMDALockoutReset] = false
}

func (c *RunChecksContext) testActionAvailable(action Action) error {
	var available bool

	switch action {
	case ActionEnableTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPMViaFirmware:
		var err error
		available, err = isPPIActionAvailable(c.env, action)
		if err != nil {
			return err
		}
	case ActionClearTPM:
		dev, err := c.env.TPMDevice()
		if err != nil {
			return err
		}

		tpm, err := tpm2.OpenTPMDevice(dev)
		if err != nil {
			return fmt.Errorf("cannot open TPM device: %w", err)
		}
		defer tpm.Close()

		perm, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyPermanent)
		if err != nil {
			return fmt.Errorf("cannot obtain the value of TPM_PT_PERMANENT: %w", err)
		}
		available = tpm2.PermanentAttributes(perm)&tpm2.AttrDisableClear == 0
	case ActionPermitNoSecureBoot:
		available = c.profileOpts&PCRProfileOptionPermitNoSecureBootPolicyProfile > 0
	}

	c.availableActions[action] = available
	return nil
}

func (c *RunChecksContext) filterUnavailableActions(actions []Action) (out []Action, err error) {
	for _, action := range actions {
		available, tested := c.availableActions[action]
		switch {
		case !tested:
			if err := c.testActionAvailable(action); err != nil {
				return nil, fmt.Errorf("cannot test whether action %q is available: %w", err)
			}
			if available := c.availableActions[action]; available {
				out = append(out, action)
			}
		case available:
			out = append(out, action)
		}
	}

	return out, nil
}

func (c *RunChecksContext) isActionExpected(action Action) bool {
	for _, expected := range c.expectedActions {
		if expected == action {
			return true
		}
	}
	return false
}

func (c *RunChecksContext) classifyRunChecksError(err error) (kind ErrorKind, args []any, errOut error) {
	if errors.Is(err, ErrVirtualMachineDetected) {
		return ErrorKindRunningInVM, nil, nil
	}
	if errors.Is(err, ErrNoTPM2Device) || errors.Is(err, ErrNoPCClientTPM) {
		return ErrorKindNoSuitableTPM2Device, nil, nil
	}
	if errors.Is(err, ErrTPMDisabled) {
		return ErrorKindTPMDeviceDisabled, nil, nil
	}
	if errors.Is(err, ErrTPMLockout) {
		return ErrorKindTPMDeviceLockout, nil, nil
	}

	var tpmhErr *TPM2HierarchyOwnedError
	if errors.As(err, &tpmhErr) {
		return ErrorKindTPMHierarchyOwned, []any{tpmhErr.Hierarchy}, nil
	}

	if errors.Is(err, ErrTPMInsufficientNVCounters) {
		return ErrorKindInsufficientTPMCounters, nil, nil
	}

	var pcrAlgErr *NoSuitablePCRAlgorithmError
	if errors.As(err, &pcrAlgErr) {
		// We have 3 possibilities here:
		// - One or more ErrPCRBankMissingFromLog errors in the BankErrs field, for
		//   algorithms supported by this package that aren't present in the log
		//   (SHA-256, SHA-384, SHA-512). If no algorithm supported by this package,
		//   testing fails with this error.
		// - One or more TPM errors in the BanksErrs field as a result of a failure to
		//   execute TPM2_PCR_Read for a specific PCR bank.
		// - One or more PCR specific errors in the PCRErrs field for a mandatory PCR,
		//   such as PCRValueMismatchError or some other arbitrary error as a result of
		//   testing the log.
		if len(pcrAlgErr.PCRErrs) == 0 {
			// Assume that all errors are in the BankErrs field and that there
			// genuinely is no appropriate bank to select. It doesn't matter what the
			// error is (ErrPCRBankMissingFromLog vs a TPM2_PCR_Read error) in this
			// case for now, unless we expose an action for adjusting the PCR allocation.
			// In this case, we'll prioritize returning an error kind for the TPM error
			// first.
			if len(pcrAlgErr.BankErrs) == 0 {
				return "", nil, errors.New("invalid NoSuitablePCRAlgorithmError")
			}
			for _, err := range pcrAlgErr.BankErrs {
				tpmRsp, ok := errorAsTPMErrorResponse(err)
				if !ok {
					continue
				}
				// We encountered a TPM error - prioritize this in the return over any other error.
				return ErrorKindTPMCommandError, []any{tpmRsp.CommandCode(), tpmRsp.ResponseCode()}, nil
			}

			// There are genuinely no suitable PCR banks.
			return ErrorKindNoSuitablePCRBank, nil, nil
		}

		// We have some PCR specific errors.
		for _, pcrs := range pcrAlgErr.PCRErrs {
			for pcr := range pcrs {
				// TODO: de-duplicate PCRs from this
				args = append(args, pcr)
			}
		}
		return ErrorKindFirmwareMeasurementError, args, nil
	}

	var emptyPcrsErr *EmptyPCRBankError
	if errors.As(err, &emptyPcrsErr) {
		return ErrorKindEmptyPCRBank, []any{emptyPcrsErr.Alg}, nil
	}

	var logErr *TCGLogError
	if errors.As(err, &logErr) {
		return ErrorKindTCGLog, nil, nil
	}

	var tpmErr *TPM2DeviceError
	if errors.As(err, *tpmErr) {
		tpmRsp, ok := errorAsTPMErrorResponse(tpmErr)
		if !ok {
			return ErrorKindUnexpectedTPMError, nil, nil
		}
		return ErrorKindTPMCommandError, []any{tpmRsp.CommandCode(), tpmRsp.ResponseCode()}, nil
	}

	if errors.Is(err, ErrNoKernelIOMMU) {
		return ErrorKindNoKernelIOMMU, nil, nil
	}

	var pfpErr *PlatformFirmwareProtectionError
	if errors.As(err, &pfpErr) {
		return ErrorKindPlatformFirmwareInsufficientProtection, nil, nil
	}

	if errors.Is(err, ErrTPMStartupLocalityNotProtected) {
		return ErrorKindTPMStartupLocalityNotProtected, nil, nil
	}

	var pfPcrErr *PlatformFirmwarePCRError
	if errors.As(err, &pfPcrErr) {
		return ErrorKindFirmwareMeasurementError, []any{internal_efi.PlatformFirmwarePCR}, nil
	}

	var pcPcrErr *PlatformConfigPCRError
	if errors.As(err, &pcPcrErr) {
		return ErrorKindFirmwareMeasurementError, []any{internal_efi.PlatformConfigPCR}, nil
	}

	if errors.Is(err, ErrVARSuppliedDriversPresent) {
		return ErrorKindVARSuppliedDriversPresent, nil, nil
	}

	var daPcrErr *DriversAndAppsPCRError
	if errors.As(err, &daPcrErr) {
		return ErrorKindFirmwareMeasurementError, []any{internal_efi.DriversAndAppsPCR}, nil
	}

	var dacPcrErr *DriversAndAppsConfigPCRError
	if errors.As(err, &dacPcrErr) {
		return ErrorKindFirmwareMeasurementError, []any{internal_efi.DriversAndAppsConfigPCR}, nil
	}

	if errors.Is(err, ErrSysPrepApplicationsPresent) {
		return ErrorKindSysPrepApplicationsPresent, nil, nil
	}
	if errors.Is(err, ErrAbsoluteComputraceActive) {
		return ErrorKindAbsolutePresent, nil, nil
	}

	var bmcPcrErr *BootManagerCodePCRError
	if errors.As(err, &bmcPcrErr) {
		return ErrorKindFirmwareMeasurementError, []any{internal_efi.BootManagerCodePCR}, nil
	}

	var bmccPcrErr *BootManagerConfigPCRError
	if errors.As(err, &bmccPcrErr) {
		return ErrorKindFirmwareMeasurementError, []any{internal_efi.BootManagerConfigPCR}, nil
	}

	if errors.Is(err, ErrNoSecureBoot) || errors.Is(err, ErrNoDeployedMode) {
		return ErrorKindInvalidSecureBootMode, nil, nil
	}
	if errors.Is(err, ErrWeakSecureBootAlgorithmDetected) {
		return ErrorKindWeakSecureBootAlgorithmsDetected, nil, nil
	}
	if errors.Is(err, ErrPreOSVerificationUsingDigests) {
		return ErrorKindPreOSDigestVerificationDetected, nil, nil
	}

	var sbPcrErr *SecureBootPolicyPCRError
	if errors.As(err, &sbPcrErr) {
		return ErrorKindFirmwareMeasurementError, []any{internal_efi.SecureBootPolicyPCR}, nil
	}

	return ErrorKindInternal, nil, nil
}

func (c *RunChecksContext) runAction(action Action, args ...any) []*ErrorKindAndActions {
	switch action {
	case ActionNone:
		// do nothing
	case ActionReboot, ActionShutdown, ActionRebootToFWSettings, ActionContactOEM, ActionContactOSVendor:
		return singleErrorKindAndActions(ErrorKindActionFailed, nil, errors.New("specified action is not implemented by this package"))
	case ActionPermitVM:
		c.flags |= PermitVirtualMachine
	case ActionEnableTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPMViaFirmware: // PPI actions
		result, err := runPPIAction(c.env, action)
		if err != nil {
			return singleErrorKindAndActions(ErrorKindActionFailed, nil, err)
		}
		var kind ErrorKind
		switch result {
		case ppi.StateTransitionShutdownRequired:
			kind = ErrorKindShutdownRequired
		case ppi.StateTransitionRebootRequired:
			kind = ErrorKindRebootRequired
		}
		return singleErrorKindAndActions(kind, nil, nil, errorKindToActions[kind]...)
	case ActionClearTPM:
		if len(args) == 0 {
			return singleErrorKindAndActions(ErrorKindMissingArgument, nil, nil)
		}

		auth, ok := args[0].([]byte)
		if !ok {
			return singleErrorKindAndActions(ErrorKindInvalidArgument, nil, nil)
		}

		dev, err := c.env.TPMDevice()
		if err != nil {
			return singleErrorKindAndActions(ErrorKindNoSuitableTPM2Device, nil, err)
		}

		tpm, err := tpm2.OpenTPMDevice(dev)
		if err != nil {
			return singleErrorKindAndActions(ErrorKindNoSuitableTPM2Device, nil, fmt.Errorf("cannot open TPM device: %w", err))
		}
		defer tpm.Close()

		tpm.LockoutHandleContext().SetAuthValue(auth)
		session, err := tpm.StartAuthSession(tpm.LockoutHandleContext(), nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256)
		if err != nil {
			return singleErrorKindAndActions(ErrorKindActionFailed, nil, fmt.Errorf("cannot start auth session: %w", err))
		}
		defer tpm.FlushContext(session)

		err = tpm.Clear(tpm.LockoutHandleContext(), session)
		switch {
		case tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandClear, 1), tpm2.IsTPMWarning(err, tpm2.WarningLockout, tpm2.CommandClear):
			// The lockout hierarchy is now unavailable
			c.markLockoutHierarchyUnavailable()
			c.expectedActions, err = c.filterUnavailableActions(c.expectedActions)
			if err != nil {
				return singleErrorKindAndActions(ErrorKindActionFailed, nil, fmt.Errorf("cannot filter unavailable actions: %w", err))
			}
			return singleErrorKindAndActions(ErrorKindTPMAuthFail, nil, fmt.Errorf("cannot clear TPM: %w", err))
		case err != nil:
			return singleErrorKindAndActions(ErrorKindActionFailed, nil, fmt.Errorf("cannot clear TPM: %w", err))
		}
	case ActionTPMDALockoutReset:
		if len(args) == 0 {
			return singleErrorKindAndActions(ErrorKindMissingArgument, nil, nil)
		}

		auth, ok := args[0].([]byte)
		if !ok {
			return singleErrorKindAndActions(ErrorKindInvalidArgument, nil, nil)
		}

		dev, err := c.env.TPMDevice()
		if err != nil {
			return singleErrorKindAndActions(ErrorKindNoSuitableTPM2Device, nil, err)
		}

		tpm, err := tpm2.OpenTPMDevice(dev)
		if err != nil {
			return singleErrorKindAndActions(ErrorKindNoSuitableTPM2Device, nil, fmt.Errorf("cannot open TPM device: %w", err))
		}
		defer tpm.Close()

		tpm.LockoutHandleContext().SetAuthValue(auth)
		session, err := tpm.StartAuthSession(tpm.LockoutHandleContext(), nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256)
		if err != nil {
			return singleErrorKindAndActions(ErrorKindActionFailed, nil, fmt.Errorf("cannot start auth session: %w", err))
		}
		defer tpm.FlushContext(session)

		err = tpm.DictionaryAttackLockReset(tpm.LockoutHandleContext(), session)
		switch {
		case tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandDictionaryAttackLockReset, 1), tpm2.IsTPMWarning(err, tpm2.WarningLockout, tpm2.CommandDictionaryAttackLockReset):
			// The lockout hierarchy is now unavailable
			c.markLockoutHierarchyUnavailable()
			c.expectedActions, err = c.filterUnavailableActions(c.expectedActions)
			if err != nil {
				return singleErrorKindAndActions(ErrorKindInternal, nil, fmt.Errorf("cannot filter unavailable actions: %w", err))
			}
			return singleErrorKindAndActions(ErrorKindTPMAuthFail, nil, fmt.Errorf("cannot reset DA counter: %w", err))
		case err != nil:
			return singleErrorKindAndActions(ErrorKindActionFailed, nil, fmt.Errorf("cannot reset DA counter: %w", err))
		}
	case ActionClearTPMHierarchyOwnership:
		if len(args) < 2 {
			return singleErrorKindAndActions(ErrorKindMissingArgument, nil, nil)
		}

		hierarchy, ok := args[0].(tpm2.Handle)
		if !ok {
			return singleErrorKindAndActions(ErrorKindInvalidArgument, nil, nil)
		}
		if hierarchy.Type() != tpm2.HandleTypePermanent {
			return singleErrorKindAndActions(ErrorKindInvalidArgument, nil, nil)
		}
		auth, ok := args[1].([]byte)
		if !ok {
			return singleErrorKindAndActions(ErrorKindInvalidArgument, nil, nil)
		}

		dev, err := c.env.TPMDevice()
		if err != nil {
			return singleErrorKindAndActions(ErrorKindNoSuitableTPM2Device, nil, err)
		}

		tpm, err := tpm2.OpenTPMDevice(dev)
		if err != nil {
			return singleErrorKindAndActions(ErrorKindNoSuitableTPM2Device, nil, fmt.Errorf("cannot open TPM device: %w", err))
		}
		defer tpm.Close()

		tpm.GetPermanentContext(hierarchy).SetAuthValue(auth)
		session, err := tpm.StartAuthSession(tpm.GetPermanentContext(hierarchy), nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256)
		if err != nil {
			return singleErrorKindAndActions(ErrorKindActionFailed, nil, fmt.Errorf("cannot start auth session: %w", err))
		}
		defer tpm.FlushContext(session)

		err = tpm.HierarchyChangeAuth(tpm.GetPermanentContext(hierarchy), nil, session)
		switch {
		case tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandHierarchyChangeAuth, 1), tpm2.IsTPMWarning(err, tpm2.WarningLockout, tpm2.CommandHierarchyChangeAuth):
			// Only the lockout hierarchy is DA protected. The lockout hierarchy is now unavailable
			c.markLockoutHierarchyUnavailable()
			c.expectedActions, err = c.filterUnavailableActions(c.expectedActions)
			if err != nil {
				return singleErrorKindAndActions(ErrorKindInternal, nil, fmt.Errorf("cannot filter unavailable actions: %w", err))
			}
			return singleErrorKindAndActions(ErrorKindTPMAuthFail, nil, fmt.Errorf("cannot clear hierarchy auth: %w", err))
		case tpm2.IsTPMSessionError(err, tpm2.ErrorBadAuth, tpm2.CommandHierarchyChangeAuth, 1):
			// All other hierarchies are DA exempt, which means we get a different error
			// for auth failure.
			return singleErrorKindAndActions(ErrorKindTPMAuthFail, nil, fmt.Errorf("cannot clear hierarchy auth: %w", err))
		case err != nil:
			return singleErrorKindAndActions(ErrorKindActionFailed, nil, fmt.Errorf("cannot clear hierarchy auth: %w", err))
		}
	case ActionPermitNoDiscreteTPMResetMitigation:
		c.flags |= PermitNoDiscreteTPMResetMitigation
	case ActionPermitEmptyPCRBanks:
		c.flags |= PermitEmptyPCRBanks
	case ActionPermitVARSuppliedDrivers:
		c.flags |= PermitVARSuppliedDrivers
	case ActionPermitSysPrepApplications:
		c.flags |= PermitSysPrepApplications
	case ActionPermitAbsolute:
		c.flags |= PermitAbsoluteComputrace
	case ActionPermitNoSecureBoot:
		c.flags &^= SecureBootPolicyProfileSupportRequired
	case ActionPermitWeakSecureBootAlgorithms:
		c.flags |= PermitWeakSecureBootAlgorithms
	case ActionPermitPreOSDigestVerification:
		c.flags |= PermitPreOSVerificationUsingDigests
	}
	return nil
}

// LastError returns the error from the last [RunChecks] invocation. If it completed
// successfully, this will return nil.
func (c *RunChecksContext) LastError() error {
	return c.lastErr
}

// Errors returns all errors from every [RunChecks] invocation.
func (c *RunChecksContext) Errors() []error {
	return c.errs
}

// Result returns the result from a successful invocation of [RunChecks]. This will
// be nil if it hasn't completed successfully yet.
func (c *RunChecksContext) Result() *CheckResult {
	return c.result
}

// Run will run the specified action, and if that completes successfully will run another
// iteration of [RunChecks] and test the result against the preferred [WithAutoTCGPCRProfile]
// configuration. On success, this will return the CheckResult and a single ErrorKindAndActions
// with the error kind ErrorKindNone. On failure, this will return one or more ErrorKindAndActions.
// If there are any actions associated with an error, the install environment may try one or more
// of them in order to try to resolve the issue that caused the error.
func (c *RunChecksContext) Run(ctx context.Context, action Action, args ...any) (*CheckResult, []*ErrorKindAndActions) {
	if !c.isActionExpected(action) {
		return nil, singleErrorKindAndActions(ErrorKindUnexpectedAction, nil, nil)

	}

	errKinds := c.runAction(action, args...)
	if len(errKinds) > 0 {
		return nil, errKinds
	}

	c.expectedActions = nil
	var kinds []*ErrorKindAndActions
	for {
		result, err := RunChecks(ctx, c.flags, c.loadedImages)
		c.result = result
		c.lastErr = err

		var profileErr error
		if err == nil {
			// If RunChecks succeeded, test the result against the profile options
			// to see if we can generate a PCR combination.
			profile := WithAutoTCGPCRProfile(result, c.profileOpts)
			_, profileErr = profile.PCRs()
		}
		if err == nil && profileErr == nil {
			// If neither step failed, break and return success.
			break
		}

		if err != nil {
			// If RunChecks failed, save it's error and return the appropriate error kinds.
			c.errs = append(c.errs, err)

			for _, unpackedErr := range unpackRunChecksErrors(err) {
				kind, args, err := c.classifyRunChecksError(unpackedErr)
				if err != nil {
					return nil, singleErrorKindAndActions(ErrorKindInternal, nil, fmt.Errorf("cannot classify error: %w", err))
				}
				jsonArgs, err := json.Marshal(args)
				if err != nil {
					return nil, singleErrorKindAndActions(ErrorKindInternal, nil, fmt.Errorf("cannot serialize error arguments: %w", err))
				}
				actions := errorKindToActions[kind]
				actions, err = c.filterUnavailableActions(actions)
				if err != nil {
					return nil, singleErrorKindAndActions(ErrorKindInternal, nil, fmt.Errorf("cannot filter unavailable actions: %w", err))
				}

				kinds = append(kinds, &ErrorKindAndActions{
					ErrorKind: kind,
					ErrorArgs: jsonArgs,
					Error:     unpackedErr,
					Actions:   actions,
				})
				c.expectedActions = append(c.expectedActions, actions...)
			}

			break
		}

		// RunChecks succeeded but there was a profile error.
		// Most errors should tell us which PCRs we're lacking support for.
		var requiredPCRsErr *UnsupportedRequiredPCRsError
		if !errors.As(profileErr, &requiredPCRsErr) {
			return nil, singleErrorKindAndActions(ErrorKindInternal, nil, fmt.Errorf("cannot test whether a PCR combination can be generated: %w", err))
		}

		// Make any PCRs we're lacking support for mandatory so that they end
		// up being returned in the RunChecks error on the next iteration,
		// which means we return a more appropriate error message.
		for _, pcr := range requiredPCRsErr.PCRs {
			switch pcr {
			case 0:
				c.flags |= PlatformFirmwareProfileSupportRequired
			case 1:
				c.flags |= PlatformConfigProfileSupportRequired
			case 2:
				c.flags |= DriversAndAppsProfileSupportRequired
			case 3:
				c.flags |= DriversAndAppsConfigProfileSupportRequired
			case 4:
				c.flags |= BootManagerCodeProfileSupportRequired
			case 5:
				c.flags |= BootManagerConfigProfileSupportRequired
			case 7:
				c.flags |= SecureBootPolicyProfileSupportRequired
			}
		}
	}

	if c.result != nil {
		return c.result, nil
	}
	return nil, kinds
}
