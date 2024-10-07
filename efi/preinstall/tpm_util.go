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

import "github.com/canonical/go-tpm2"

// TPMResponse represents any type that can provide information about a
// TPM command and its response code/
type TPMResponse interface {
	CommandCode() tpm2.CommandCode
	ResponseCode() tpm2.ResponseCode
}

func errorAsTPMErrorResponse(err error) (TPMResponse, bool) {
	tpmErr := tpm2.AsTPMError(err, tpm2.AnyErrorCode, tpm2.AnyCommandCode)
	if tpmErr != nil {
		return tpmErr, true
	}
	tpmWarn := tpm2.AsTPMWarning(err, tpm2.AnyWarningCode, tpm2.AnyCommandCode)
	if tpmWarn != nil {
		return tpmWarn, true
	}
	vendorErr := tpm2.AsTPMVendorError(err, tpm2.AnyVendorResponseCode, tpm2.AnyCommandCode)
	if vendorErr != nil {
		return vendorErr, true
	}

	return nil, false
}
