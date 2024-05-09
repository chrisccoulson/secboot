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
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/tcglog-parser"
)

var (
	ErrUEFIDebuggerPresent = errors.New("a UEFI debugger endpoint is present")
)

type secureBootPolicyResultFlags int

const (
	secureBootConfigCompletionSignalsOSPresent secureBootPolicyResultFlags = 1 << iota
	secureBootVerificationIncludesWeakAlg
)

type secureBootPolicyResult struct {
	usedAuthorities []*x509.Certificate
	flags           secureBootPolicyResultFlags
}

func checkSecureBootPolicyMeasurementsAndObtainAuthorities(log *tcglog.Log) (result *secureBootPolicyResult, err error) {
	// Make sure that secure boot is enabled - we don't generate PCR7 policies for systems
	// without secure boot enabled.
	secureBoot, err := efi.ReadSecureBootVariable()
	if err != nil {
		return nil, fmt.Errorf("cannot read SecureBoot variable: %w", err)
	}
	if !secureBoot {
		return nil, errors.New("generating secure boot profiles with secure boot disabled is not supported")
	}

	// On UEFI 2.5 and later, we require that deployed mode is enabled, because this changes the
	// sequence of events for PCR7.
	// TODO(chrisccoulson): relax this later on in the profile generation to support user mode, but
	// maybe add a new flag (RequireDeployedMode or AllowUserMode) to DetectSupport. We should be
	// able to generate policies for user mode.
	if efi.IsDeployedModeSupported() {
		secureBootMode, err := efi.ComputeSecureBootMode()
		if err != nil {
			return nil, fmt.Errorf("cannot compute secure boot mode: %w", err)
		}
		if secureBootMode != efi.DeployedMode {
			return nil, errors.New("generating secure boot profiles when not in deployed mode is currently not supported")
		}
	}

	osIndicationsSupported, err := efi.ReadOSIndicationsSupportedVariable()
	if err != nil {
		return nil, fmt.Errorf("cannot read OsIndicationsSupported variable: %w", err)
	}
	if osIndicationsSupported&efi.OSIndicationTimestampRevocation > 0 {
		// Timestamp verification relies on another database (dbt) which we currently don't support
		// when generating the profile for PCR7. It's theoretically possible we might see this in the
		// wild and might have to add support for it in the future.
		return nil, errors.New("generating secure boot profiles with timestamp revocation (dbt) is currently not supported")
	}
	if osIndicationsSupported&efi.OSIndicationStartOSRecovery > 0 {
		// OS recovery relies on another database (dbr) which we currently don't support when generating
		// the profile for PCR7, but given this also depends on EFI_VARIABLE_AUTHENTICATION_3, it's unlikely
		// we'll ever see this in the wild.
		return nil, errors.New("generating secure boot profiles with OS recovery options which requires dbr support is not supported")
	}
	// TODO(chrisccoulson): Not sure if there's any indication that we might get SPDM related measurements,
	// which our profile generation for PCR7 currently doesn't support.

	// Make sure config in the log is measured in the expected order.
	configs := []efi.VariableDescriptor{
		{Name: "SecureBoot", GUID: efi.GlobalVariable},
		{Name: "PK", GUID: efi.GlobalVariable},
		{Name: "KEK", GUID: efi.GlobalVariable},
		{Name: "db", GUID: efi.ImageSecurityDatabaseGuid},
		{Name: "dbx", GUID: efi.ImageSecurityDatabaseGuid},
		// TODO: Add optional dbt / SPDM in the future.
	}

	result = new(secureBootPolicyResult)
	var db efi.SignatureDatabase
	var inOsPresent bool

	// Iterate over the secure boot configuration
	events := log.Events
	for len(events) > 0 {
		// Pop next event
		ev := events[0]
		events = events[1:]

		if ev.PCRIndex < tcglog.PCRIndex(secureBootPolicyPCR) && ev.EventType == tcglog.EventTypeSeparator {
			inOsPresent = true
			if len(configs) > 0 {
				return nil, errors.New("secure boot config not fully measured before transition to OS-present")
			}
			result.flags |= secureBootConfigCompletionSignalsOSPresent
			continue
		}

		if ev.PCRIndex != tcglog.PCRIndex(secureBootPolicyPCR) {
			// Not PCR7
			continue
		}
		if ev.EventType == tcglog.EventTypeSeparator {
			// We're done with the configuration - note than on modern firmwares, this
			// does not indicate the pre-OS to OS-present transition - only separators
			// in PCRs 0-6 do this. Some verification events may occur after this as
			// part of the pre-OS environment, eg, launching embedded drivers and option
			// ROMs, loading system preparation applications etc.
			// Some older firmwares measure separators to PCRs 0-7 as part of this
			// transition, but then it's not clear where verification events for pre-OS
			// launches go.
			break
		}

		// Check the event type
		switch ev.EventType {
		case tcglog.EventTypeEFIVariableDriverConfig:
			// ok
		case tcglog.EventTypeEFIAction:
			// it's ok to see this as the first PCR7 event to indicate the presence of
			// a firmware debugger endpoint.
			switch {
			case len(configs) == 0 || configs[0].Name == "SecureBoot":
				// This isn't the first PCR7 event
			case ev.Data == tcglog.FirmwareDebuggerEvent:
				// We've got a UEFI debugger enabled - we don't support generating PCR7
				// policies to accommodate this.
				// TODO(chrisccoulson): Perhaps modify the WithSecureBootPolicyProfile
				// code to generate profiles to accommodate this in the future to support
				// debugging, via an optional AllowUEFIDebbuger flag to DetectSupport.
				return nil, ErrUEFIDebuggerPresent
			}
			// If we didn't return an error already, fall through to the generic error.
			fallthrough
		default:
			return nil, fmt.Errorf("unexpected config log event type %v", ev.EventType)
		}

		if len(configs) == 0 {
			// Unexpected config event
			return nil, errors.New("unexpected config event")
		}

		// Pop the next secure boot config name
		config := configs[0]
		configs = configs[1:]

		// Decode event data and make sure that the names match
		data, ok := ev.Data.(*tcglog.EFIVariableData)
		if !ok {
			// decode failure types are guaranteed to implement the error interface
			return nil, fmt.Errorf("%s variable event has wrong data format: %w", config.Name, ev.Data.(error))
		}
		if data.VariableName != config.GUID || data.UnicodeName != config.Name {
			return nil, fmt.Errorf("out of order measurement - unexpected event (expected %s-%v, got %s-%v)", config.Name, config.GUID, data.UnicodeName, data.VariableName)
		}

		switch data.UnicodeName {
		case "SecureBoot":
			// Make sure the SecureBoot value in the log matches the EFI variable.
			// We don't do this for other variables because they can be updated from
			// the OS, making them inconsistent.
			expected := []byte{0}
			if secureBoot {
				expected = []byte{1}
			}
			if !bytes.Equal(data.VariableData, expected) {
				return nil, errors.New("SecureBoot variable and log mismatch")
			}
		case "PK":
			// Make sure that we can parse the database and it contains a single entry
			pk, err := efi.ReadSignatureDatabase(bytes.NewReader(data.VariableData))
			if err != nil {
				return nil, fmt.Errorf("cannot decode PK contents: %w", err)
			}
			switch len(pk) {
			case 0:
				return nil, errors.New("empty PK when secure boot is enabled")
			case 1:
				esl := pk[0]
				if esl.Type != efi.CertX509Guid {
					return nil, fmt.Errorf("PK signature list has an unexpected type: %v", esl.Type)
				}
				if len(esl.Signatures) != 1 {
					return nil, fmt.Errorf("PK signature list has an unexpected number of signatures (%d)", len(esl.Signatures))
				}
				if _, err := x509.ParseCertificate(esl.Signatures[0].Data); err != nil {
					return nil, fmt.Errorf("cannot decode PK certificate: %w", err)
				}
				// ok
			default:
				return nil, errors.New("invalid PK contents: more than one signature list")
			}
		case "db":
			// Capture the db from the log for future use.
			var err error
			db, err = efi.ReadSignatureDatabase(bytes.NewReader(data.VariableData))
			if err != nil {
				return nil, fmt.Errorf("cannot decode db contents: %w", err)
			}
		default:
			// Make sure that we can parse the database
			if _, err = efi.ReadSignatureDatabase(bytes.NewReader(data.VariableData)); err != nil {
				return nil, fmt.Errorf("cannot decode %s contents: %w", data.UnicodeName, err)
			}
		}
	}

	if len(configs) > 0 {
		// not all of the mandatory secure boot configs were measured. We'll fail to generate
		// a valid policy in this case.
		return nil, errors.New("missing config events")
	}

	// Iterate over the secure boot verifications, capturing authorities that were used from db
	// on the current boot.
	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.PCRIndex < tcglog.PCRIndex(secureBootPolicyPCR) && ev.EventType == tcglog.EventTypeSeparator {
			inOsPresent = true
			continue
		}
		if ev.PCRIndex != tcglog.PCRIndex(secureBootPolicyPCR) {
			// Not PCR7
			continue
		}

		if ev.EventType != tcglog.EventTypeEFIVariableAuthority {
			if !inOsPresent {
				return nil, fmt.Errorf("unexpected event type for post-config pre-OS verification event: %v", ev.EventType)
			}
			// permit different event types during OS present depending on what
			// OS loaders do - we'll just skip these.
			continue
		}

		// Decode the verification event
		varData, ok := ev.Data.(*tcglog.EFIVariableData)
		if !ok {
			// if decoding failed, the resulting data is guaranteed to implement error.
			return nil, fmt.Errorf("verification event has wrong data format: %w", ev.Data.(error))
		}
		if varData.VariableName != efi.ImageSecurityDatabaseGuid || varData.UnicodeName != "db" {
			// skip verification events not from db
			if !inOsPresent {
				// all pre-OS verification events should come from db
				return nil, fmt.Errorf("pre-OS verification event is not from db (got %s-%v)", varData.UnicodeName, varData.VariableName)
			}
			continue
		}

		// Construct a signature data entry from the event data
		esd := new(efi.SignatureData)
		r := bytes.NewReader(varData.VariableData)
		owner, err := efi.ReadGUID(r)
		if err != nil {
			return nil, fmt.Errorf("cannot decode owner GUID from verification event: %w", err)
		}
		esd.Owner = owner
		data, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("cannot read data from verification event: %w", err)
		}
		esd.Data = data

		// Match it to db entry
		var matchedEntry *efi.SignatureList
		for _, list := range db {
			for _, sig := range list.Signatures {
				if sig.Equal(esd) {
					matchedEntry = list
					break
				}
			}
			if matchedEntry != nil {
				break
			}
		}
		if matchedEntry == nil {
			return nil, fmt.Errorf("found db verification event that doesn't match to any db signature list")
		}
		switch matchedEntry.Type {
		case efi.CertX509Guid:
			cert, err := x509.ParseCertificate(esd.Data)
			if err != nil {
				return nil, fmt.Errorf("cannot decode X.509 certificate from db verification event: %w", err)
			}
			result.usedAuthorities = append(result.usedAuthorities, cert)

			switch cert.PublicKeyAlgorithm {
			case x509.RSA:
				pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
				if !ok {
					return nil, errors.New("db verification event includes X.509 certificate with unsupported public key type")
				}
				if pubKey.N.BitLen() <= 1024 {
					result.flags |= secureBootVerificationIncludesWeakAlg
				}
			default:
				return nil, errors.New("db verification event includes X.509 certificate with unsupported public key algorithm")
			}
			// XXX: unfortunately the verification event only includes the CA certificate - it's not possible from this to
			// determine the actual signing certificate, it's signature algorithm, and the algorithm used for signing the
			// binary.
		case efi.CertSHA1Guid:
			result.flags |= secureBootVerificationIncludesWeakAlg
		}
	}

	return result, nil
}
