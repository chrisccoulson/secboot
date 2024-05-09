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

	"github.com/canonical/tcglog-parser"
)

type platformFirmwareResultFlags int

const (
	platformFirmwareNonHostCodePresent platformFirmwareResultFlags = 1 << iota
)

func checkPlatformFirmwareMeasurements(log *tcglog.Log) (result platformFirmwareResultFlags, err error) {
	// Iterate over the log until OS-present and make sure that we have expected
	// event types
	events := log.Events
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.PCRIndex != tcglog.PCRIndex(platformFirmwarePCR) {
			// Not PCR0
			continue
		}
		if ev.EventType == tcglog.EventTypeSeparator {
			break
		}

		switch ev.EventType {
		case tcglog.EventTypePostCode:
			// ok, but deprecated
		case tcglog.EventTypeNoAction:
			// ok
		case tcglog.EventTypeSCRTMContents:
			// ok
		case tcglog.EventTypeSCRTMVersion:
			// ok
		case tcglog.EventTypeNonhostCode:
			result |= platformFirmwareNonHostCodePresent
		case tcglog.EventTypeNonhostInfo:
			result |= platformFirmwareNonHostCodePresent
		case tcglog.EventTypePostCode2:
			// ok
		case tcglog.EventTypeEFIBootServicesDriver:
			// ok
		case tcglog.EventTypeEFIRuntimeServicesDriver:
			// ok
		case tcglog.EventTypeEFIPlatformFirmwareBlob:
			// ok, but deprecated
		case tcglog.EventTypeEFIPlatformFirmwareBlob2:
			// ok
		case tcglog.EventTypeEFIHCRTMEvent:
			// ok
		case tcglog.EventTypeEFISPDMFirmwareBlob:
			// ok
		default:
			return 0, fmt.Errorf("unexpected pre-OS log event type %v", ev.EventType)
		}
	}

	// Nothing should measure to PCR0 outside of pre-OS - we'll generate an invalid profile
	// if it does.
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.PCRIndex == tcglog.PCRIndex(platformFirmwarePCR) {
			return 0, errors.New("firmware measures events as part of the OS-present environment")
		}
	}

	return result, nil
}
