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
	"github.com/snapcore/secboot/efi/internal"
)

type (
	// DetectVirtMode controls what type of virtualization to test for.
	DetectVirtMode = internal.DetectVirtMode
)

const (
	// DetectVirtModeAll detects for all types of virtualization.
	DetectVirtModeAll = internal.DetectVirtModeAll

	// DetectVirtModeContainer detects for container types of virtualization.
	DetectVirtModeContainer = internal.DetectVirtModeContainer

	// DetectVirtModeVM detects for fully virtualized types of environments.
	DetectVirtModeVM = internal.DetectVirtModeVM
)

// VirtModeNone corresponds to no virtualization.
const VirtModeNone = internal.VirtModeNone

var (
	// ErrNoTPM2Device is returned from HostEnvironment.TPMDevice if no TPM2
	// device is available.
	ErrNoTPM2Device = internal.ErrNoTPM2Device

	// ErrNotAMD64Host is returned from HostEnvironment.AMD64 on environments that
	// are not AMD64.
	ErrNotAMD64Host = internal.ErrNotAMD64Host

	// ErrNoDeviceAttribute is returned from SysfsDevice.Attribute if the supplied attribute
	// does not exist.
	ErrNoDeviceAttribute = internal.ErrNoDeviceAttribute
)

// SysfsDevice corresponds to a device in the sysfs tree.
type SysfsDevice = internal.SysfsDevice

// HostEnvironmentAMD64 is an interface that abstracts out a host environment specific
// to AMD64 platforms.
type HostEnvironmentAMD64 = internal.HostEnvironmentAMD64

// HostEnvironment is an interface that abstracts out a host environment, so that
// consumers of the API can provide ways to mock parts of an environment.
type HostEnvironment = internal.HostEnvironment
