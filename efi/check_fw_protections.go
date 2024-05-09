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

import "errors"

var (
	ErrCPUDebugEnabledOrAvailable = errors.New("CPU debugging features are enabled or available")
	ErrNoIOMMUSupport             = errors.New("no IOMMU support")
)

type NoHCRTMError struct {
	err error
}

func (e *NoHCRTMError) Error() string {
	return "no HCRTM available to protect the integrity of the platform firmware: " + e.err.Error()
}

func (e *NoHCRTMError) Unwrap() error {
	return e.err
}
