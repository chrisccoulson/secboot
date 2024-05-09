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
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
)

type authorityTrust int

const (
	authorityTrustBootCode authorityTrust = 1 << iota // authority is trusted to load boot code (we don't need PCR4)
	authorityTrustDrivers                             // authority is trusted to load drivers (we may not need PCR2)
)

type authorityTrustDataSet []authorityTrustData

func (s authorityTrustDataSet) determineTrust(certs []*x509.Certificate) authorityTrust {
	trust := authorityTrustBootCode | authorityTrustDrivers
	for _, cert := range certs {
		var certTrust authorityTrust
		for _, auth := range s {
			if !bytes.Equal(auth.authority.subject, cert.RawSubject) {
				continue
			}
			if !bytes.Equal(auth.authority.subjectKeyId, cert.SubjectKeyId) {
				continue
			}
			if auth.authority.publicKeyAlgorithm == cert.PublicKeyAlgorithm {
				continue
			}
			certTrust = auth.trust
			break
		}
		trust &= certTrust
	}

	return trust
}

func (s authorityTrustDataSet) trustedForBootManager(certs []*x509.Certificate) bool {
	return s.determineTrust(certs)&authorityTrustBootCode > 0
}

func (s authorityTrustDataSet) trustedForDrivers(certs []*x509.Certificate) bool {
	return s.determineTrust(certs)&authorityTrustDrivers > 0
}

type authorityTrustData struct {
	authority *secureBootAuthorityIdentity
	trust     authorityTrust
}

var (
	knownCAs = authorityTrustDataSet{
		{msUefiCA2011, 0},
	}
)

var (
	ErrVARSuppliedDriversPresent       = errors.New("value added retailer supplied drivers were detected to be running")
	ErrSysprepAppsPresent              = errors.New("system preparation applications were detected to be running")
	ErrVARSuppliedFirmwareAppsPresent  = errors.New("value added retailer supplied firmware applications were detected to be running")
	ErrWeakSecureBootAlgorithmDetected = errors.New("a weak cryptographic algorithm was detected during secure boot verification")
)

type TPM2DeviceError struct {
	err error
}

func (e *TPM2DeviceError) Error() string {
	return "error with TPM2 device: " + e.err.Error()
}

func (e *TPM2DeviceError) Unwrap() error {
	return e.err
}

type TCGLogError struct {
	err error
}

func (e *TCGLogError) Error() string {
	return "error with TCG log: " + e.err.Error()
}

func (e *TCGLogError) Unwrap() error {
	return e.err
}

type PlatformFirmwareProtectionError struct {
	err error
}

func (e *PlatformFirmwareProtectionError) Error() string {
	return "error with platform firmware protection configuration: " + e.err.Error()
}

func (e *PlatformFirmwareProtectionError) Unwrap() error {
	return e.err
}

type PlatformFirmwareError struct {
	err error
}

func (e *PlatformFirmwareError) Error() string {
	return "error with platform firmware (PCR0) measurements: " + e.err.Error()
}

func (e *PlatformFirmwareError) Unwrap() error {
	return e.err
}

type DriversAndAppsError struct {
	err error
}

func (e *DriversAndAppsError) Error() string {
	return "error with drivers and apps (PCR2) measurements: " + e.err.Error()
}

func (e *DriversAndAppsError) Unwrap() error {
	return e.err
}

type BootManagerCodeError struct {
	err error
}

func (e *BootManagerCodeError) Error() string {
	return "error with boot manager code (PCR4) measurements: " + e.err.Error()
}

func (e *BootManagerCodeError) Unwrap() error {
	return e.err
}

type SecureBootError struct {
	err error
}

func (e *SecureBootError) Error() string {
	return "error with secure boot policy (PCR7) measurements: " + e.err.Error()
}

func (e *SecureBootError) Unwrap() error {
	return e.err
}

type resultFlags uint32

const (
	secureBootPolicyOk            resultFlags = 1 << iota // the WithSecureBootPolicyProfile option should work for PCR7
	bootManagerCodeOk                                     // the WithBootManagerCodeProfile option should work for PCR4
	driversAndAppsOk                                      // the WithDriversAndAppsProfile option should work for PCR2
	platformFirmwareOk                                    // the WithPlatformFirmwareProfile option should work for PCR0
	nonHostCodePresent                                    // PCR0 indicates the presence of non host code running on embedded controllers (do we care about checking for this?)
	varDriversPresent                                     // PCR2 indicates that drivers from addons or which are potentially value-added-retailer provided are running on the host
	varNonHostCodePresent                                 // PCR2 indicates the presence of non host code running on value-added-retailer embedded controllers (do we care about checking for this?)
	sysprepAppsPresent                                    // PCR4 indicates that system preparation applications are running (before the pre-OS to OS-present transition)
	varFirmwareAppsPresent                                // PCR4 indicates that value-added-retailer provided applications are running before the OS loads
	sbConfigEndMeansOSPresent                             // PCR7 indicates that the end of the secure boot configuration measurements is tied to the transition to OS-present.
	sbVerificationIncludesWeakAlg                         // PCR7 indicates that a secure boot verification used a weak algorithm, such as a SHA-1 digest or a CA cert with a 1024-bit RSA pubkey.
)

type PCRProfileOptionsFlags uint32

const (
	// PCRProfileOptionsDefault is the default PCR configuration
	PCRProfileOptionsDefault PCRProfileOptionsFlags = 0

	// PCRProfileOptionsMostSecure is the most secure configuration by
	// including all relevant TCG defined PCRs supported by this package
	// (0, 2, 4, and 7)
	PCRProfileOptionsMostSecure PCRProfileOptionsFlags = 1 << iota

	// PCRProfileOptionsTrustCAsForBootCode can omit PCR4 if the authorized
	// signature database contains CAs that are not directly trusted to sign
	// boot code. This should only be used by a user who makes a decision to
	// trust these CAs themselves.
	PCRProfileOptionsTrustCAsForBootCode

	// PCRProfileOptionsTrustCAsForVARSuppliedDrivers can omit PCR2 (when paired with
	// PCRProfileOptionsTrustVARSuppliedNonHostCode) if the authorized signature
	// database contains CAs that are not directly trusted to sign UEFI drivers. This
	// should only be used by a user who makes a decision to trust these CAs
	// themselves.
	PCRProfileOptionsTrustCAsForVARSuppliedDrivers

	// PCRProfileOptionsTrustVARSuppliedNonHostCode can omit PCR2 if a user decides that
	// they trust non host code running on embedded controllers in value-added-retailer
	// components - this is code that not part of the host's trust chain but may still
	// affect trust in the platform
	PCRProfileOptionsTrustVARSuppliedNonHostCode
)

// PCRProfileAutoEnablePCRsOption is an option for AddPCRProfile that adds one or more PCRs.
type PCRProfileAutoEnablePCRsOption interface {
	PCRProfileEnablePCRsOption
	Choose(flags PCRProfileOptionsFlags) PCRProfileAutoEnablePCRsOption
}

type pcrProfileAutoSetPcrsOption struct {
	PCRProfileEnablePCRsOption

	resultFlags   resultFlags         // populated by DetectSupport
	secureBootCAs []*x509.Certificate // CAs used to verify components during the boot when DetectSupport ran

	flags PCRProfileOptionsFlags // user supplied flags to customize the set of PCRs
}

func newPcrProfileAutoSetPcrsOption(resultFlags resultFlags, secureBootCAs []*x509.Certificate, flags PCRProfileOptionsFlags) *pcrProfileAutoSetPcrsOption {
	out := &pcrProfileAutoSetPcrsOption{
		resultFlags:   resultFlags,
		secureBootCAs: secureBootCAs,
		flags:         flags,
	}
	out.PCRProfileEnablePCRsOption = out
	return out
}

var errPCRProfileOptions = newPcrProfileAutoSetPcrsOption(0, nil, 0)

func (o *pcrProfileAutoSetPcrsOption) options() ([]PCRProfileEnablePCRsOption, error) {
	switch {
	case o.flags&PCRProfileOptionsMostSecure > 0:
		if o.flags != PCRProfileOptionsMostSecure {
			return nil, errors.New("PCRProfileOptionsMostSecure can only be used on its own")
		}
		if o.resultFlags&(secureBootPolicyOk|bootManagerCodeOk|driversAndAppsOk|platformFirmwareOk) != (secureBootPolicyOk | bootManagerCodeOk | driversAndAppsOk | platformFirmwareOk) {
			return nil, errors.New("PCRProfileOptionsMostSecure does not work becuase of one or more of PCRs 0, 2, 4 or 7 failed earlier checks")
		}
		return []PCRProfileEnablePCRsOption{
			WithPlatformFirmwareProfile(),
			WithDriversAndAppsProfile(),
			WithBootManagerCodeProfile(),
			WithSecureBootPolicyProfile(),
		}, nil
	default:
		var opts []PCRProfileEnablePCRsOption
		if o.resultFlags&secureBootPolicyOk > 0 {
			// If PCR7 usage is ok, always include it
			opts = append(opts, WithSecureBootPolicyProfile())

			// Check if we need to include PCR4
			if !knownCAs.trustedForBootManager(o.secureBootCAs) && o.flags&PCRProfileOptionsTrustCAsForBootCode == 0 {
				// one or more CAs used for verification are not trusted for boot code and we're not configured to override trust here, so include PCR4
				if o.resultFlags&bootManagerCodeOk == 0 {
					return nil, errors.New("one or more CAs used for secure boot verification are not trusted to authenticate boot code and " +
						"PCRProfileOptionsTrustCAsForBootCode was not supplied to bypass this, but PCR 4 failed earlier checks")
				}
				opts = append(opts, WithBootManagerCodeProfile())
			}

			isPcr2Supported := o.resultFlags&driversAndAppsOk > 0

			includePcr2 := o.flags&PCRProfileOptionsTrustVARSuppliedNonHostCode == 0
			if includePcr2 && !isPcr2Supported {
				return nil, errors.New("options didn't include PCRProfileOptionsTrustVARSuppliedNonHostCode to bypass value-added-retailer supplied non-host code, but PCR2 failed earlier checks")
			}
			if !knownCAs.trustedForDrivers(o.secureBootCAs) && o.flags&PCRProfileOptionsTrustCAsForVARSuppliedDrivers == 0 {
				// one or more CAs used verification are not trusted for VAR supplied drivers or apps and we're not configured to override trust here, so include PCR2
				includePcr2 = true
				if !isPcr2Supported {
					return nil, fmt.Errorf("one or more CAs used for secure boot verification are not trusted to authenticate value-added-retailer supplied drivers " +
						"and PCRProfileOptionsTrustCAsForVARSuppliedDrivers was not supplied to bypass this, but PCR 2 failed earlier checks")
				}
			}
			if includePcr2 {
				opts = append(opts, WithDriversAndAppsProfile())
			}
		} else {
			if o.flags&(PCRProfileOptionsTrustCAsForBootCode|PCRProfileOptionsTrustCAsForVARSuppliedDrivers) > 0 {
				return nil, errors.New("PCRProfileOptionsTrustCAsForBootCode and PCRProfileOptionsTrustCAsForVARSuppliedDrivers are not compatible when PCR7 can't be used")
			}

			// We can't use PCR7, so we must include PCRs 2 and 4. These can't be omitted.
			if o.resultFlags&bootManagerCodeOk == 0 {
				return nil, errors.New("PCR7 failed earlier checks, making PCR 4 mandatory, but this failed earlier checks as well")
			}
			if o.resultFlags&driversAndAppsOk == 0 {
				return nil, errors.New("PCR7 failed earlier checks, making PCR 2 mandatory, but this failed earlier checks as well")
			}
			opts = append(opts, WithDriversAndAppsProfile(), WithBootManagerCodeProfile())

		}
		return opts, nil
	}
}

func (o *pcrProfileAutoSetPcrsOption) applyOptionsTo(gen *pcrProfileGenerator) error {
	opts, err := o.options()
	if err != nil {
		return fmt.Errorf("cannot select an appropriate set of TCG defined PCR profiles with the current options: %w", err)
	}
	for i, opt := range opts {
		if err := opt.applyOptionTo(gen); err != nil {
			return fmt.Errorf("cannot add PCR profile option %d: %w", i, err)
		}
	}
	return nil
}

func (o *pcrProfileAutoSetPcrsOption) Choose(flags PCRProfileOptionsFlags) PCRProfileAutoEnablePCRsOption {
	return newPcrProfileAutoSetPcrsOption(o.resultFlags, o.secureBootCAs, flags)
}

func (o *pcrProfileAutoSetPcrsOption) PCRs() (tpm2.HandleList, error) {
	opts, err := o.options()
	if err != nil {
		return nil, fmt.Errorf("cannot select an appropriate set of TCG defined PCR profiles with the current options: %w", err)
	}

	var out tpm2.HandleList
	for i, opt := range opts {
		pcrs, err := opt.PCRs()
		if err != nil {
			return nil, fmt.Errorf("cannot add PCRs from profile option %d: %w", i, err)
		}
		out = append(out, pcrs...)
	}
	return out, nil
}

type DetectFlags int

const (
	// PermitNoSecureBootPolicyProfileSupport means that [WithSecureBootPolicyProfile]
	// is not required to work.
	PermitNoSecureBootPolicyProfileSupport DetectFlags = 1 << iota

	// PermitNoBootManagerCodeProfileSupport means that [WithBootManagerCodeProfile]
	// is not required to work.
	PermitNoBootManagerCodeProfileSupport

	// PermitNoDriversAndAppsProfileSupport means that [WithDriversAndAppsProfile]
	// is not required to work.
	PermitNoDriversAndAppsProfileSupport

	// PermitNoPlatformFirmwareProfileSupport means that [WithPlatformFirmwareProfile]
	// is not required to work.
	PermitNoPlatformFirmwareProfileSupport

	// PermitVARSuppliedDrivers will prevent [DetectSupport] from returning an error if the
	// platform is running any value-added-retailer embedded drivers, which are included in a
	// PCR policy when using [WithDriversAndAppsProfile].
	PermitVARSuppliedDrivers

	// PermitSysPrepApplications will prevent [DetectSupport] from returning an error if the
	// platform boot contained any system preparation applications, which are included in a PCR
	// policy when using [WithBootManagerCodeProfile]. These may increase fragility of PCR4 values
	// if they are outside of the control of the OS.
	PermitSysPrepApplications

	// PermitVARSuppliedFirmwareApplications will prevent [DetectSupport] from returning an error
	// if the platform boot contained any value-added-retailer suppplied applications that run
	// before the OS, such as endpoint management solutions. These are included in a PCR policy when
	// using [WithBootManagerCodeProfile]. These inherently increase fragility of PCR4 values because
	// it makes them more dependendent on firmware updates where we may not be able to predict new
	// PCR values.
	PermitVARSuppliedFirmwareApplications

	// AllowWeakSecureBootAlgorithms will ensure [WithSecureBootPolicyProfile] isn't marked as unsupported
	// if any verification events on the current boot indicate the presence of weak algorithms, such as
	// authenticating a binary with SHA1, or a CA with a 1024-bit RSA public key. This does have some
	// limitations because the log doesn't indicate the properties of the actual signing certificate or the
	// algorithms used to sign a binary.
	AllowWeakSecureBootAlgorithms
)

func DetectSupport(flags DetectFlags) (pcrAlg tpm2.HashAlgorithmId, options PCRProfileAutoEnablePCRsOption, err error) {
	tpm, err := openAndCheckTPM2Device()
	if err != nil {
		return tpm2.HashAlgorithmNull, errPCRProfileOptions, &TPM2DeviceError{err}
	}
	defer tpm.Close()

	// Grab the TCG log
	log, err := defaultEnv.ReadEventLog()
	if err != nil {
		return tpm2.HashAlgorithmNull, errPCRProfileOptions, &TCGLogError{err}
	}

	pcrAlg, err = checkFirmwareLogAndChoosePCRBank(tpm, log)
	switch {
	case tpm2.IsTPMError(err, tpm2.AnyErrorCode, tpm2.AnyCommandCode):
		return tpm2.HashAlgorithmNull, errPCRProfileOptions, &TPM2DeviceError{err}
	case err != nil:
		return tpm2.HashAlgorithmNull, errPCRProfileOptions, &TCGLogError{err}
	}

	var resultFlags resultFlags

	if err := checkPlatformFirmwareProtections(); err != nil {
		return tpm2.HashAlgorithmNull, errPCRProfileOptions, &PlatformFirmwareProtectionError{err}
	}

	pcr0Result, err := checkPlatformFirmwareMeasurements(log)
	switch {
	case err != nil && flags&PermitNoPlatformFirmwareProfileSupport == 0:
		return tpm2.HashAlgorithmNull, errPCRProfileOptions, &PlatformFirmwareError{err}
	case err != nil:
		// ignore this error
	default:
		resultFlags |= platformFirmwareOk
		if pcr0Result&platformFirmwareNonHostCodePresent > 0 {
			resultFlags |= nonHostCodePresent
		}
	}

	pcr2Result, err := checkDriversAndAppsMeasurements(log)
	switch {
	case err != nil && flags&PermitNoDriversAndAppsProfileSupport == 0:
		return tpm2.HashAlgorithmNull, errPCRProfileOptions, &DriversAndAppsError{err}
	case err != nil:
		// ignore this error
	default:
		resultFlags |= driversAndAppsOk
		if pcr2Result&driversAndAppsDriversPresent > 0 {
			resultFlags |= varDriversPresent
		}
		if pcr2Result&driversAndAppsNonHostCodePresent > 0 {
			resultFlags |= varNonHostCodePresent
		}

		if resultFlags&varDriversPresent > 0 && flags&PermitVARSuppliedDrivers == 0 {
			return tpm2.HashAlgorithmNull, errPCRProfileOptions, ErrVARSuppliedDriversPresent
		}
	}

	pcr4Result, err := checkBootManagerCodeMeasurements(log)
	switch {
	case err != nil && flags&PermitNoBootManagerCodeProfileSupport == 0:
		return tpm2.HashAlgorithmNull, errPCRProfileOptions, &BootManagerCodeError{err}
	case err != nil:
		// ignore this error
	default:
		resultFlags |= bootManagerCodeOk

		if pcr4Result&bootManagerCodeSysprepAppsPresent > 0 {
			resultFlags |= sysprepAppsPresent
		}
		if pcr4Result&bootManagerCodeVARFirmwareAppsPresent > 0 {
			resultFlags |= varFirmwareAppsPresent
		}

		if resultFlags&sysprepAppsPresent > 0 && flags&PermitSysPrepApplications == 0 {
			return tpm2.HashAlgorithmNull, errPCRProfileOptions, ErrSysprepAppsPresent
		}
		if resultFlags&varFirmwareAppsPresent > 0 && flags&PermitVARSuppliedFirmwareApplications == 0 {
			return tpm2.HashAlgorithmNull, errPCRProfileOptions, ErrVARSuppliedFirmwareAppsPresent
		}
	}

	var usedAuthorities []*x509.Certificate
	pcr7Result, err := checkSecureBootPolicyMeasurementsAndObtainAuthorities(log)
	switch {
	case err != nil && flags&PermitNoSecureBootPolicyProfileSupport == 0:
		return tpm2.HashAlgorithmNull, errPCRProfileOptions, &SecureBootError{err}
	case err != nil:
		// ignore this error
	default:
		resultFlags |= secureBootPolicyOk
		if pcr7Result.flags&secureBootConfigCompletionSignalsOSPresent > 0 {
			resultFlags |= sbConfigEndMeansOSPresent
		}
		if pcr7Result.flags&secureBootVerificationIncludesWeakAlg > 0 {
			resultFlags |= sbVerificationIncludesWeakAlg
		}
		usedAuthorities = pcr7Result.usedAuthorities

		if resultFlags&sbVerificationIncludesWeakAlg > 0 && flags&AllowWeakSecureBootAlgorithms == 0 {
			resultFlags &^= secureBootPolicyOk
			if flags&PermitNoSecureBootPolicyProfileSupport == 0 {
				return tpm2.HashAlgorithmNull, errPCRProfileOptions, &SecureBootError{ErrWeakSecureBootAlgorithmDetected}
			}
		}
	}

	if resultFlags&sbConfigEndMeansOSPresent > 0 {
		if resultFlags&(sysprepAppsPresent|varDriversPresent) > 0 {
			// The UEFI spec and TCG PFP spec are ambiguous here, but the specs
			// suggest that the transition from pre-OS to OS-present is indicated by
			// EV_SEPARATOR events in PCRs 0-7. The separator in PCR7 also demarcates
			// secure boot configuration and secure boot verification, so if separators
			// are measured to PCRs 0-7 at the same time, where do verification events
			// for pre-OS code go (embedded drivers, system preparation applications etc)?
			//
			// The way EDK2 does this is it uses a EV_SEPARATOR in PCR7 to demarcate secure
			// boot configuration and secure boot verification. This happens earlier than the
			// transition from pre-OS to OS-present, which in EDK2 is indicated by EV_SEPARATOR
			// events being measured later to PCRs 0-6.
			//
			// If our testing of PCR7 shows that its EV_SEPARATOR is part of the pre-OS to
			// OS-present transition, but our testing of PCRs 2 and 4 indicate that there are
			// embedded drivers and system preparation applications, then any associated
			// verification events will end up being omitted by code that runs as part of
			// WithSecureBootPolicyProfile. If we hit this condition here, just disable support
			// for PCR7.
			resultFlags &^= secureBootPolicyOk
			if flags&PermitNoSecureBootPolicyProfileSupport == 0 {
				return tpm2.HashAlgorithmNull, errPCRProfileOptions, &SecureBootError{errors.New("system preparation applications or value-added-retailer supplied drivers present, " +
					"but PCR7 indicates it has no support for properly logging verification events for these")}
			}
		}
	}

	return pcrAlg, newPcrProfileAutoSetPcrsOption(resultFlags, usedAuthorities, 0), nil
}
