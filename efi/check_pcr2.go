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

type driversAndAppsResultFlags int

const (
	driversAndAppsDriversPresent driversAndAppsResultFlags = 1 << iota
	driversAndAppsNonHostCodePresent
)

func checkDriversAndAppsMeasurements(log *tcglog.Log) (result driversAndAppsResultFlags, err error) {
	// Iterate over the log until OS-present and make sure we have expected
	// event types.
	events := log.Events
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.PCRIndex != tcglog.PCRIndex(driversAndAppsPCR) {
			// Not PCR2
			continue
		}
		if ev.EventType == tcglog.EventTypeSeparator {
			break
		}

		switch ev.EventType {
		case tcglog.EventTypeAction:
			// ok
		case tcglog.EventTypeNonhostCode:
			result |= driversAndAppsNonHostCodePresent
		case tcglog.EventTypeNonhostInfo:
			// This shouldn't be measured into PCR2, but is on my XPS15
			result |= driversAndAppsNonHostCodePresent
		case tcglog.EventTypeEFIBootServicesApplication:
			result |= driversAndAppsDriversPresent
		case tcglog.EventTypeEFIBootServicesDriver:
			result |= driversAndAppsDriversPresent
		case tcglog.EventTypeEFIRuntimeServicesDriver:
			result |= driversAndAppsDriversPresent
		case tcglog.EventTypeEFIAction:
			// ok
		case tcglog.EventTypeEFIPlatformFirmwareBlob:
			result |= driversAndAppsDriversPresent
		case tcglog.EventTypeEFIPlatformFirmwareBlob2:
			result |= driversAndAppsDriversPresent
		case tcglog.EventTypeEFISPDMFirmwareBlob:
			result |= driversAndAppsDriversPresent
		default:
			return 0, fmt.Errorf("unexpected pre-OS log event type %v", ev.EventType)
		}
	}

	// Nothing should measure to PCR2 outside of pre-OS - we'll generate an invalid profile
	// if it does.
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.PCRIndex == tcglog.PCRIndex(driversAndAppsPCR) {
			return 0, errors.New("firmware measures events as part of the OS-present environment")
		}
	}

	return result, nil
}
