// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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

package secboot

import (
	"encoding/json"
)

// ActivationError describes how an unlock attempt failed with a platform
// protected key.
type ActivationError string

const (
	// ActivationErrorInvalidKeyData indicates that an unlock attempt
	// failed because the associated key data was invalid in some way.
	ActivationErrorInvalidKeyData ActivationError = "invalid-key-data"

	// ActivationErrorDeviceUninitialized indicates that an unlock attempt
	// failed because the platform's secure device is not properly
	// initialized. This is a hint to the OS to execute the necessary
	// provisioning of the device.
	ActivationErrorDeviceUninitialized ActivationError = "device-uninitialized"

	// ActivationErrorDeviceUnavailable indicates that an unlock attempt
	// failed because the platform's secure device is currently unavailable.
	// It may have been made unavailable by the platform's firmware or
	// may be temporarily unavailable for some other reason (eg, a TPM in
	// dictionary attack lockout mode).
	ActivationErrorDeviceUnavailable ActivationError = "device-unavailable"

	// ActivationErrorCryptsetup indicates that an unlock attempt failed
	// because systemd-cryptsetup returned an error, despite the associated
	// key being recovered from the platform's secure device. This could
	// be because the recovered key does not match any keyslot on the
	// device.
	ActivationErrorCryptsetup ActivationError = "cryptsetup"
)

// FailedActivationAttempt describes why an unlock attempt failed with
// a specific platform protected key.
type FailedActivationAttempt struct {
	// Key is the unique ID of the KeyData associated with this
	// failed attempt.
	Key KeyID `json:"key"`

	// Error describes the reason that this attempt failed.
	Error ActivationError `json:"error"`
}

// VolumeActivationResult contains the result of an attempt to unlock
// a LUKS container.
type VolumeActivationResult struct {
	// SourceDevicePath is the device path of the encrypted container.
	// This is important for repair scenarios as this is where the LUKS
	// header is.
	SourceDevicePath string `json:"source-device-path"`

	// VolumeName is the device mapper name for the unlocked volume.
	VolumeName string `json:"volume-name"`

	// Key is the unique ID of the KeyData used to unlock this LUKS
	// volume. If the volume was not unlocked or was unlocked by an
	// alternative mechanism, then this will be empty.
	Key KeyID `json:"key,omitempty"`

	// FailedAttempts contains a list of failed activation attempts.
	FailedAttempts []FailedActivationAttempt `json:"failed-attempts"`
}

// ActivationState keeps a record of LUKS2 container unlock attempts
// with platform protected keys during early boot, in a format that can
// be serialized to JSON for sharing between early boot and the OS runtime.
// It mantains a list of VolumeActivationResults, with each one being
// associated with a single volume identified by the name used during
// unlocking.
type ActivationState struct {
	results []*VolumeActivationResult
}

func (s ActivationState) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.results)
}

func (s *ActivationState) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &s.results)
}

// LookupResultByVolumeName returns the VolumeActivationResult associated
// with the supplied name. If no result exists yet, this will return nil.
func (s ActivationState) LookupResultByVolumeName(name string) *VolumeActivationResult {
	for _, r := range s.results {
		if r.VolumeName == name {
			return r
		}
	}
	return nil
}

func (s *ActivationState) activationResult(sourceDevicePath, volumeName string) *VolumeActivationResult {
	r := s.LookupResultByVolumeName(volumeName)
	switch {
	case r != nil && r.SourceDevicePath != sourceDevicePath:
		panic("record found with wrong source device path: " + r.SourceDevicePath)
	case r != nil:
		return r
	default:
		r := &VolumeActivationResult{
			SourceDevicePath: sourceDevicePath,
			VolumeName:       volumeName}
		s.results = append(s.results, r)
		return r
	}
}

// RecordActivationFailure records that the device could not be activated with the
// platform protected key with the specified ID for the given reason. This will automatically
// create a record for the volume with the supplied name. If a record already exists, it
// must be associated with the same device.
//
// This can be called multiple times. It cannot be called once RecordActivationSuccess has
// been called for the volume.
func (s *ActivationState) RecordActivationFailure(volumeName, sourceDevicePath string, key KeyID, err ActivationError) {
	r := s.activationResult(sourceDevicePath, volumeName)
	if len(r.Key) > 0 {
		panic("cannot record failure after success")
	}
	r.FailedAttempts = append(r.FailedAttempts, FailedActivationAttempt{Key: key, Error: err})
}

// RecordActivationSuccess records that the device was successfully activated with the
// platform protected key with the specified ID. This will automatically create a record
// for the volume with the supplied name. If a record already exists (because of a previous
// call to RecordActivationFailure), it must be associated with the same device.
//
// This can only be called once for volumeName.
func (s *ActivationState) RecordActivationSuccess(volumeName, sourceDevicePath string, key KeyID) {
	r := s.activationResult(sourceDevicePath, volumeName)
	if len(r.Key) != 0 {
		panic("cannot record more than one success")
	}
	r.Key = key
}
