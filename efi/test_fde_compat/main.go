package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/canonical/go-tpm2"
	"github.com/jessevdk/go-flags"
	"github.com/snapcore/secboot/efi"
)

type options struct {
	Detect struct {
		PermitVARSuppliedDrivers bool `long:"permit-var-supplied-drivers" description:"Permit value-added-retailer supplied firmware drivers to be running"`
		PermitSysPrepApps        bool `long:"permit-sysprep-apps" description:"Permit system preparation applications to be running"`
		PermitVARFirmwareApps    bool `long:"permit-var-supplied-firmware-apps" description:"Permit value-added-retailer supplied firmware agents to be running before the OS starts"`
		AllowWeakSecureBootAlgs  bool `long:"allow-weak-secure-boot-algs" description:"Allow weak secure boot algorithms to be used during verification"`
	} `group:"Detect options"`

	Profile struct {
		MostSecure                    bool `long:"most-secure" description:"Select the most secure PCR profile"`
		TrustCAsForBootCode           bool `long:"trust-authorities-for-boot-code" description:"Trust the secure boot CAs used to authenticate code on this system to authenticate any boot code"`
		TrustCAsForVARSuppliedDrivers bool `long:"trust-authorities-for-var-supplied-drivers" description:"Trust the secure boot CAs used to authenticate code on this system to authenticate any value-added-retailer supplied firmware driver"`
		TrustVARSuppliedNonHostCode   bool `long:"trust-var-supplied-nonhost-code" description:"Trust code running in value-added-retailer supplied embedded controllers. This code doesn't run on the CPU and isn't part of the trust chain, but may affect trust"`
		TrustPlatformFirmware         bool `long:"trust-platform-firmware" description:"Trust the platform firmware that is running, even if it isn't secured by verified boot"`
	} `group:"PCR profile select options"`
}

var opts options

func run() error {
	if _, err := flags.Parse(&opts); err != nil {
		return err
	}

	var detectFlags efi.DetectFlags

	if opts.Detect.PermitVARSuppliedDrivers {
		detectFlags |= efi.PermitVARSuppliedDrivers
	}
	if opts.Detect.PermitSysPrepApps {
		detectFlags |= efi.PermitSysPrepApplications
	}
	if opts.Detect.PermitVARFirmwareApps {
		detectFlags |= efi.PermitVARSuppliedFirmwareApplications
	}
	if opts.Detect.AllowWeakSecureBootAlgs {
		detectFlags |= efi.AllowWeakSecureBootAlgorithms
	}

	var alg tpm2.HashAlgorithmId
	var pcrOpts efi.PCRProfileAutoEnablePCRsOption

	i := 0
	for {
		i += 1
		fmt.Println("Running DetectSupport, attempt", i)
		var err error
		alg, pcrOpts, err = efi.DetectSupport(detectFlags)
		if err == nil {
			fmt.Println("DetectSupport completed without an error")
			fmt.Println()
			break
		}

		fmt.Printf("DetectSupport returned an error: %v\n", err)

		var sbe *efi.SecureBootError
		if errors.As(err, &sbe) {
			detectFlags |= efi.PermitNoSecureBootPolicyProfileSupport
			fmt.Println("...retrying with PermitNoSecureBootPolicyProfileSupport")
			fmt.Println()
			continue
		}
		var bmce *efi.BootManagerCodeError
		if errors.As(err, &bmce) {
			detectFlags |= efi.PermitNoBootManagerCodeProfileSupport
			fmt.Println("...retrying with PermitNoBootManagerCodeProfileSupport")
			fmt.Println()
			continue
		}
		var dae *efi.DriversAndAppsError
		if errors.As(err, &dae) {
			detectFlags |= efi.PermitNoDriversAndAppsProfileSupport
			fmt.Println("...retrying with PermitNoDriversAndAppsProfileSupport")
			fmt.Println()
			continue
		}
		var pfe *efi.PlatformFirmwareError
		if errors.As(err, &pfe) {
			detectFlags |= efi.PermitNoPlatformFirmwareProfileSupport
			fmt.Println("...retrying with PermitNoPlatformFirmwareProfileSupport")
			fmt.Println()
			continue
		}
		if err != nil {
			return fmt.Errorf("DetectSupport returned an error: %w", err)
		}
	}

	var pcrFlags efi.PCRProfileOptionsFlags
	if opts.Profile.MostSecure {
		pcrFlags |= efi.PCRProfileOptionsMostSecure
	}
	if opts.Profile.TrustCAsForBootCode {
		pcrFlags |= efi.PCRProfileOptionsTrustCAsForBootCode
	}
	if opts.Profile.TrustCAsForVARSuppliedDrivers {
		pcrFlags |= efi.PCRProfileOptionsTrustCAsForVARSuppliedDrivers
	}
	if opts.Profile.TrustVARSuppliedNonHostCode {
		pcrFlags |= efi.PCRProfileOptionsTrustVARSuppliedNonHostCode
	}
	if opts.Profile.TrustPlatformFirmware {
		pcrFlags |= efi.PCRProfileOptionsTrustPlatformFirmware
	}
	pcrOpts = pcrOpts.Choose(pcrFlags)

	pcrs, err := pcrOpts.PCRs()
	if err != nil {
		return fmt.Errorf("cannot select an appropriate set of PCRs: %w", err)
	}

	fmt.Println("Selected PCR algorithm:", alg)
	fmt.Println("Selected TCG PCRs:", pcrs)

	return nil
}

func main() {
	if err := run(); err != nil {
		switch e := err.(type) {
		case *flags.Error:
			// flags already prints this
			if e.Type != flags.ErrHelp {
				os.Exit(1)
			}
		default:
			fmt.Fprintln(os.Stderr, "This platform is not suitable for FDE:", err)
			os.Exit(1)
		}
	}
}
