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
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
)

type NoSuitablePCRAlgorithmError struct {
	err error
}

func (e *NoSuitablePCRAlgorithmError) Error() string {
	return "no suitable PCR algorithm available: " + e.err.Error()
}

func (e *NoSuitablePCRAlgorithmError) Unwrap() error {
	return e.err
}

// checkFirmwareLogAgainstTPMForAlg checks the supplied TCG log consistency against the TPM PCRs
// for the specified algorithm. This only checks TCG defined PCRs (0-7).
func checkFirmwareLogAgainstTPMForAlg(tpm *tpm2.TPMContext, log *tcglog.Log, alg tpm2.HashAlgorithmId) error {
	digestMap := map[tcglog.PCRIndex]tpm2.Digest{
		0: make(tpm2.Digest, alg.Size()),
		1: make(tpm2.Digest, alg.Size()),
		2: make(tpm2.Digest, alg.Size()),
		3: make(tpm2.Digest, alg.Size()),
		4: make(tpm2.Digest, alg.Size()),
		5: make(tpm2.Digest, alg.Size()),
		6: make(tpm2.Digest, alg.Size()),
		7: make(tpm2.Digest, alg.Size()),
	}

	for i, ev := range log.Events {
		if ev.PCRIndex > tcglog.PCRIndex(secureBootPolicyPCR) {
			// Not a TCG event
			continue
		}
		if ev.EventType == tcglog.EventTypeNoAction {
			// Not measured
			if startupLocality, isStartupLocality := ev.Data.(*tcglog.StartupLocalityEventData); isStartupLocality {
				if ev.PCRIndex != tcglog.PCRIndex(platformFirmwarePCR) {
					return fmt.Errorf("unexpected StartupLocality event in PCR %d", ev.PCRIndex)
				}
				if !bytes.Equal(digestMap[0], make(tpm2.Digest, alg.Size())) {
					return errors.New("unexpected StartupLocality event")
				}
				digestMap[0][alg.Size()-1] = startupLocality.StartupLocality
			}
			continue
		}

		measured := false
		for evAlg, digest := range ev.Digests {
			// Find the matching digest
			if evAlg != alg {
				// Not the right algorithm
				continue
			}

			// Perform a hash extend
			h := alg.NewHash()
			h.Write(digestMap[ev.PCRIndex])
			h.Write(digest)
			digestMap[ev.PCRIndex] = h.Sum(nil)
			measured = true
			break
		}
		if !measured {
			return fmt.Errorf("missing digest for PCR %d, event %d", ev.PCRIndex, i)
		}
	}

	// Read the actual PCR values from the TPM.
	pcrs := tpm2.PCRSelectionList{{Hash: alg, Select: []int{0, 1, 2, 3, 4, 5, 6, 7}}}
	_, values, err := tpm.PCRRead(pcrs)
	if err != nil {
		return err
	}

	// Compare that the actual PCR values are consistent with the log.
	for pcr, digest := range values[alg] {
		if !bytes.Equal(digest, digestMap[tcglog.PCRIndex(pcr)]) {
			return fmt.Errorf("PCR value mismatch at PCR %d (actual %#x, expected %#x)", pcr, digest, digestMap[tcglog.PCRIndex(pcr)])
		}
	}

	return nil

}

// checkFirmwareLogAndChoosePCRBank verifies that the firmware TCG log is in crypto-agile form and
// consistent with at least one supported PCR bank for the TCG defined PCRs.
func checkFirmwareLogAndChoosePCRBank(tpm *tpm2.TPMContext, log *tcglog.Log) (tpm2.HashAlgorithmId, error) {
	// Make sure it's a crypto-agile log
	if !log.Spec.IsEFI_2() {
		return tpm2.HashAlgorithmNull, errors.New("invalid spec")
	}

	// Chose the best PCR bank, ordered from SHA-512, SHA-384 to SHA-256.
	chosenPcrAlg := tpm2.HashAlgorithmNull
	var lastErr error
	for _, alg := range []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA512, tpm2.HashAlgorithmSHA384, tpm2.HashAlgorithmSHA256} {
		err := checkFirmwareLogAgainstTPMForAlg(tpm, log, alg)
		if err != nil && (!tpm2.IsTPMError(err, tpm2.AnyErrorCode, tpm2.AnyCommandCode) || lastErr == nil) {
			lastErr = err
		}
		if err == nil {
			chosenPcrAlg = alg
			break
		}
	}
	if chosenPcrAlg == tpm2.HashAlgorithmNull {
		// No suitable PCR banks to use :(
		return tpm2.HashAlgorithmNull, &NoSuitablePCRAlgorithmError{lastErr}
	}

	// Make sure we have no error EV_SEPARATORS and that no events are measured from the pre-OS
	// environment to PCR8 and beyond
	var seen int
	for _, ev := range log.Events {
		if ev.PCRIndex > tcglog.PCRIndex(secureBootPolicyPCR) {
			return tpm2.HashAlgorithmNull, fmt.Errorf("measurements made by firmware from pre-OS environment to non-TCG defined PCR %d", ev.PCRIndex)
		}
		if ev.EventType != tcglog.EventTypeSeparator {
			continue
		}
		seen += 1
		data, ok := ev.Data.(*tcglog.SeparatorEventData)
		if !ok {
			// if it failed to decode then it's guaranteed to implement error.
			return tpm2.HashAlgorithmNull, fmt.Errorf("invalid event data for separator in PCR %d: %w", ev.PCRIndex, ev.Data.(error))
		}
		if data.IsError() {
			return tpm2.HashAlgorithmNull, fmt.Errorf("error separator for PCR %d (error code in log: %d)", ev.PCRIndex, binary.LittleEndian.Uint32(data.Bytes()))
		}
		if seen >= 8 {
			// we've seen separators for all TCG defined PCRs
			break
		}
	}

	return chosenPcrAlg, nil
}
