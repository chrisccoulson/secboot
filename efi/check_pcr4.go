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
	"bytes"
	"errors"
	"fmt"
	"strings"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/tcglog-parser"
)

func readLoadOptionFromLog(log *tcglog.Log, n uint16) (*efi.LoadOption, error) {
	events := log.Events
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.PCRIndex != tcglog.PCRIndex(hostPlatformConfigPCR) {
			continue
		}
		if ev.EventType == tcglog.EventTypeSeparator {
			break
		}

		if ev.EventType != tcglog.EventTypeEFIVariableBoot && ev.EventType != tcglog.EventTypeEFIVariableBoot2 {
			// not a boot variable
			continue
		}

		data, ok := ev.Data.(*tcglog.EFIVariableData)
		if !ok {
			// decode error data is guaranteed to implement the error interface
			return nil, fmt.Errorf("boot variable measurement has wrong data format: %w", ev.Data.(error))
		}
		if data.VariableName != efi.GlobalVariable {
			// not a global variable
			continue
		}
		if !strings.HasPrefix(data.UnicodeName, "Boot") || len(data.UnicodeName) != 8 {
			// name has unexpected prefix or length
			continue
		}

		var x uint16
		if y, err := fmt.Sscanf(data.UnicodeName, "Boot%x", &x); err != nil || y != 1 {
			continue
		}
		if x != n {
			// wrong load option
			continue
		}

		// We've found the correct load option
		opt, err := efi.ReadLoadOption(bytes.NewReader(data.VariableData))
		if err != nil {
			return nil, fmt.Errorf("cannot read load option from event data: %w", err)
		}
		return opt, nil
	}

	return nil, errors.New("cannot find specified boot option")
}

type applicationType int

const (
	applicationTypeLoadOption applicationType = iota + 1
	applicationTypeVARFirmwareAgent
)

func classifyApplicationLaunch(ev *tcglog.Event, bootOpts []*efi.LoadOption) (appType applicationType, bootOptsOut []*efi.LoadOption, err error) {
	if ev.EventType != tcglog.EventTypeEFIBootServicesApplication {
		panic("unexpected event type")
	}
	data, ok := ev.Data.(*tcglog.EFIImageLoadEvent)
	if !ok {
		// the data resulting from decode errors is guaranteed to implement error
		return 0, nil, fmt.Errorf("EV_EFI_BOOT_SERVICES_APPLICATION event has wrong data format: %w", ev.Data.(error))
	}
	if len(data.DevicePath) == 0 {
		return 0, nil, errors.New("empty device path for image load event")
	}

	// Try to find a match with a load option first. Consume it if a match is found.
	bootOptsTmp := bootOpts
	for len(bootOptsTmp) > 0 {
		opt := bootOptsTmp[0]
		bootOptsTmp = bootOptsTmp[1:]

		if opt.Attributes&efi.LoadOptionActive == 0 {
			continue
		}

		if data.DevicePath.Matches(opt.FilePath) != efi.DevicePathNoMatch {
			// On the balance of probabilities, this is most likely a launch of a load
			// option, given that we have some sort of path match with it.
			return applicationTypeLoadOption, bootOptsTmp, nil
		}
	}

	if _, isFv := data.DevicePath[0].(efi.MediaFvDevicePathNode); isFv {
		// Loaded from flash, which is the test that the profile generation
		// uses to assume an application is a firmware agent in order to preserve
		// its launch event if it occurs in the OS-present phase.
		return applicationTypeVARFirmwareAgent, bootOpts, nil
	}

	return 0, nil, errors.New("cannot determine the class of application launched")
}

type bootManagerCodeResultFlags int

const (
	bootManagerCodeSysprepAppsPresent bootManagerCodeResultFlags = 1 << iota
	bootManagerCodeVARFirmwareAppsPresent
)

func checkBootManagerCodeMeasurements(log *tcglog.Log) (result bootManagerCodeResultFlags, err error) {
	opts, err := efi.ReadBootOptionSupportVariable()
	if err != nil {
		return 0, fmt.Errorf("cannot obtain boot option support: %w", err)
	}
	sysprepSupported := opts&efi.BootOptionSupportSysPrep > 0

	var sysprepOpts []*efi.LoadOption
	if sysprepSupported {
		sysprepOpts, err = efi.ReadOrderedLoadOptionVariables(efi.LoadOptionClassSysPrep)
		switch {
		case errors.Is(err, efi.ErrVarNotExist):
			// ignore
		case err != nil:
			return 0, fmt.Errorf("cannot read SysPrep load options: %w", err)
		}
	}

	// Iterate over the log until OS-present and make sure we have expected
	// event types.
	var expectingSeparator bool
	events := log.Events
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.PCRIndex != tcglog.PCRIndex(bootManagerCodePCR) {
			// Not PCR4
			continue
		}
		if ev.EventType == tcglog.EventTypeSeparator {
			break
		}
		if expectingSeparator {
			return 0, fmt.Errorf("unexpected event type %v: expecting transition from pre-OS to OS-present event", ev.EventType)
		}

		switch {
		case ev.EventType == tcglog.EventTypeOmitBootDeviceEvents:
			// ok
		case ev.EventType == tcglog.EventTypeEFIAction:
			// ok, although 1.05 of the TCG PFP spec is a bit ambiguous here, section 8.2.4 says
			// the event associated with the first boot attempt, if it is measured, occurs before
			// the separator (as part of pre-OS). The actual PCR usage section 3.3.4.5 in this version
			// of the spec and older contradicts this and mentions a bunch of EV_ACTION events that
			// pertain to BIOS boot. On every device we've tested, this event occurs before the
			// separator and there are no BIOS boot related EV_ACTION events. 1.06 of the TCG PFP
			// spec tries to clean this up a bit, removing reference to the EV_ACTION events and
			// correcting the "Method for measurement" subsection of section 3.3.4.5 to match
			// section 8.2.4. We reject any EV_ACTION events in PCR4 here anyway.
			if ev.Data == tcglog.EFICallingEFIApplicationEvent {
				// The next event we're expecting is the pre-OS to OS-present transition.
				//
				// TODO(chrisccoulson): The TCG PFP spec 1.06 r49 expects there to be a
				// EV_EFI_ACTION event immediately following this one with the string
				// "Booting to <Boot####> Option". Whilst the current profile generation code
				// will preserve what's currently in the log, there needs to be an API for boot
				// configuration code to specificy the actual boot option to ensure that we
				// predict the correct value. We currently fail support for PCR4 if this
				// unsupported EV_EFI_ACTION event is present next.
				expectingSeparator = true
			} else {
				return 0, fmt.Errorf("unexpected EV_EFI_ACTION event %q", ev.Data.String())
			}
		case ev.EventType == tcglog.EventTypeEFIBootServicesApplication:
			// A pre-OS application launch
			var class applicationType
			var err error
			class, sysprepOpts, err = classifyApplicationLaunch(ev, sysprepOpts)
			if err != nil {
				return 0, fmt.Errorf("cannot classify pre-OS application launch for event %v: %w", ev, err)
			}
			switch class {
			case applicationTypeLoadOption:
				result |= bootManagerCodeSysprepAppsPresent
			case applicationTypeVARFirmwareAgent:
				result |= bootManagerCodeVARFirmwareAppsPresent
			}
		default:
			return 0, fmt.Errorf("unexpected pre-OS log event type %v", ev.EventType)
		}
	}

	current, err := efi.ReadBootCurrentVariable()
	if err != nil {
		return 0, fmt.Errorf("cannot read BootCurrent variable: %w", err)
	}
	bootOpt, err := readLoadOptionFromLog(log, current)
	if err != nil {
		return 0, fmt.Errorf("cannot read current Boot%04x load option from log: %w", current, err)
	}

	// Iterate over the OS-present events until we hit the boot option launch, making sure any
	// firmware agent launches are before this, else the profile generation for PCR4 will
	// generate the wrong values.
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.PCRIndex != tcglog.PCRIndex(bootManagerCodePCR) {
			// Not PCR4
			continue
		}

		if ev.EventType != tcglog.EventTypeEFIBootServicesApplication {
			return 0, fmt.Errorf("unexpected OS-present log event type %v", ev.EventType)
		}

		class, _, err := classifyApplicationLaunch(ev, []*efi.LoadOption{bootOpt})
		if err != nil {
			return 0, fmt.Errorf("cannot classify OS-present application launch for event %v: %w", ev, err)
		}

		var seenBootOpt bool
		switch class {
		case applicationTypeLoadOption:
			seenBootOpt = true
		case applicationTypeVARFirmwareAgent:
			result |= bootManagerCodeVARFirmwareAppsPresent
		}
		if seenBootOpt {
			break
		}
	}

	// Make sure there aren't any other firmware agent launches after processing the boot option
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.PCRIndex != tcglog.PCRIndex(bootManagerCodePCR) {
			// Not PCR4
			continue
		}

		if ev.EventType != tcglog.EventTypeEFIBootServicesApplication {
			// ignore these as we assume OS loaders can use other types
			continue
		}

		class, _, err := classifyApplicationLaunch(ev, nil)
		if err != nil {
			// ok, probably a launch of a secondary stage
			continue
		}
		if class == applicationTypeVARFirmwareAgent {
			return 0, fmt.Errorf("value-added-retailer supplied firmware agent launch after processing the boot option (event %v)", ev)
		}
	}

	return result, nil
}
