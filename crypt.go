// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/snapcore/secboot/internal/luks2"

	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

const userKeyring = -4

var (
	tokenType        = "secboot"          // The type used for all secboot tokens
	slotTypeKey      = "secboot-type"     // The key used to identify the type of secboot keyslot associated with a token
	masterSlotType   = "master-detached"  // Used to idenfity a master keyslot with detached metadata
	recoverySlotType = "recovery"         // Used to identify a recovery keyslot
	tpmSlotType      = "tpm"              // Used to identify a TPM protected keyslot
	tpmSlotDataKey   = "secboot-tpm-data" // The key used for the TPM metadata for a keyslot

	luks2Activate = luks2.Activate
)

// RecoveryKey corresponds to a 16-byte recovery key in its binary form.
type RecoveryKey [16]byte

func (k RecoveryKey) String() string {
	var u16 [8]uint16
	for i := 0; i < 8; i++ {
		u16[i] = binary.LittleEndian.Uint16(k[i*2:])
	}
	return fmt.Sprintf("%05d-%05d-%05d-%05d-%05d-%05d-%05d-%05d", u16[0], u16[1], u16[2], u16[3], u16[4], u16[5], u16[6], u16[7])
}

// ParseRecoveryKey interprets the supplied string and returns the corresponding RecoveryKey. The recovery key is a
// 16-byte number, and the formatted version of this is represented as 8 5-digit zero-extended base-10 numbers (each
// with a range of 00000-65535) which may be separated by an optional '-', eg:
//
// "61665-00531-54469-09783-47273-19035-40077-28287"
//
// The formatted version of the recovery key is designed to be able to be inputted on a numeric keypad.
func ParseRecoveryKey(s string) (out RecoveryKey, err error) {
	for i := 0; i < 8; i++ {
		if len(s) < 5 {
			return RecoveryKey{}, errors.New("incorrectly formatted: insufficient characters")
		}
		x, err := strconv.ParseUint(s[0:5], 10, 16)
		if err != nil {
			return RecoveryKey{}, xerrors.Errorf("incorrectly formatted: %w", err)
		}
		binary.LittleEndian.PutUint16(out[i*2:], uint16(x))

		// Move to the next 5 digits
		s = s[5:]
		// Permit each set of 5 digits to be separated by an optional '-', but don't allow the formatted key to end or begin with one.
		if len(s) > 1 && s[0] == '-' {
			s = s[1:]
		}
	}

	if len(s) > 0 {
		return RecoveryKey{}, errors.New("incorrectly formatted: too many characters")
	}

	return
}

func isExitError(err error) bool {
	var e *exec.ExitError
	return xerrors.As(err, &e)
}

func askPassword(sourceDevicePath, msg string) (string, error) {
	cmd := exec.Command(
		"systemd-ask-password",
		"--icon", "drive-harddisk",
		"--id", filepath.Base(os.Args[0])+":"+sourceDevicePath,
		msg)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return "", err
	}
	result, err := out.ReadString('\n')
	if err != nil {
		return "", xerrors.Errorf("cannot read result from systemd-ask-password: %w", err)
	}
	return strings.TrimRight(result, "\n"), nil
}

func getPassword(sourceDevicePath, description string, reader io.Reader) (string, error) {
	if reader != nil {
		scanner := bufio.NewScanner(reader)
		switch {
		case scanner.Scan():
			return scanner.Text(), nil
		case scanner.Err() != nil:
			return "", xerrors.Errorf("cannot obtain %s from scanner: %w", description, scanner.Err())
		}
	}
	return askPassword(sourceDevicePath, "Please enter the "+description+" for disk "+sourceDevicePath+":")
}

// KeyRecoverError corresponds to an error returned from KeyRecoverContext.Recover.
type KeyRecoverError int

const (
	// KeyRecoverUnexpectedError indicates an error that was unexpected and doesn't have a more appropriate error code.
	KeyRecoverUnexpectedError KeyRecoverError = iota + 1

	// KeyRecoverNoSuitableKeystoreError indicates that a key protector was asked to recover a key without being
	// provided a suitable connection to a keystore backend.
	KeyRecoverNoSuitableKeystoreError

	// KeyRecoverKeystoreTemporarilyUnavailableError indicates that the keystore backend is temporarily unable to recover
	// a key. In the case of a TPM, this could be because the TPM's dictionary attack protection has been triggered.
	KeyRecoverKeystoreTemporarilyUnavailableError

	// KeyRecoverKeystoreProvisioningError indicates that a key protector was asked to recover a key using a keystore that
	// isn't properly provisioned.
	KeyRecoverKeystoreProvisioningError

	// KeyRecoverInvalidKeyDataError indicates that a key protector couldn't recover a key because the provided data was invalid.
	KeyRecoverInvalidKeyDataError

	// KeyRecoverPINFailError indicates that a key protector couldn't recover a key because the supplied PIN was incorrect.
	KeyRecoverPINFailError

	// KeyRecoverIncorrectKeyError indicates that a key protector appeared to successfully recover a key, but that key is not
	// a valid key to activate the LUKS volume.
	KeyRecoverIncorrectKeyError
)

func (e KeyRecoverError) Error() string {
	switch e {
	case KeyRecoverUnexpectedError:
		return "unexpected error"
	case KeyRecoverNoSuitableKeystoreError:
		return "no suitable keystore connection was provided for this key"
	case KeyRecoverKeystoreTemporarilyUnavailableError:
		return "the keystore is temporarily unavailable for recovering keys"
	case KeyRecoverKeystoreProvisioningError:
		return "the keystore is not correctly provisioned"
	case KeyRecoverInvalidKeyDataError:
		return "the key data is invalid"
	case KeyRecoverPINFailError:
		return "the supplied PIN is incorrect"
	default:
		return "unrecognized error code"
	}
}

func isKeyRecoverError(err error, code KeyRecoverError) bool {
	var e KeyRecoverError
	return xerrors.As(err, &e) && e == code
}

// KeyRecoverContext is created by an implementer of KeyProtectorHandler and corresponds to a single key.
type KeyRecoverContext interface {
	PINRequired() bool // Indicate whether a PIN is required in order to recover the key associated with this context

	// Recover will attempt to recover the key associated with this context using the supplied PIN and one
	// of the provided keystores.
	Recover(stores KeyStores, pin string) ([]byte, error)

	// DidUseKeyForDevice indicates that the key associated with this context was used to activate a volume with the
	// specified device path. Implementations can use this to add data to the kernel keyring if required.
	DidUseKeyForDevice(devicePath string)
}

type tpmKeyRecoverContext struct {
	k *SealedKeyObject
	// TODO: Add a field for the policy authorization key
}

func (c *tpmKeyRecoverContext) PINRequired() bool {
	return c.k.AuthMode2F() == AuthModePIN
}

func (c *tpmKeyRecoverContext) Recover(stores KeyStores, pin string) ([]byte, error) {
	var tpm *TPMConnection
	for _, s := range stores {
		t, ok := s.(*TPMConnection)
		if ok {
			tpm = t
			break
		}
	}

	if tpm == nil {
		return nil, KeyRecoverNoSuitableKeystoreError
	}

	key, err := c.k.UnsealFromTPM(tpm, pin)
	if err == ErrTPMProvisioning {
		// ErrTPMProvisioning in this context might indicate that there isn't a valid persistent SRK. Have a go at creating one now and then
		// retrying the unseal operation - if the previous SRK was evicted, the TPM owner hasn't changed and the storage hierarchy still
		// has a null authorization value, then this will allow us to unseal the key without requiring any type of manual recovery. If the
		// storage hierarchy has a non-null authorization value, ProvionTPM will fail. If the TPM owner has changed, ProvisionTPM might
		// succeed, but UnsealFromTPM will fail with InvalidKeyFileError when retried.
		if pErr := ProvisionTPM(tpm, ProvisionModeWithoutLockout, nil); pErr == nil {
			key, err = c.k.UnsealFromTPM(tpm, pin)
		}
	}

	switch {
	case xerrors.Is(err, ErrTPMLockout):
		return nil, KeyRecoverKeystoreTemporarilyUnavailableError
	case xerrors.Is(err, ErrTPMProvisioning):
		return nil, KeyRecoverKeystoreProvisioningError
	case isInvalidKeyFileError(err):
		return nil, KeyRecoverInvalidKeyDataError
	case xerrors.Is(err, ErrPINFail):
		return nil, KeyRecoverPINFailError
	case err != nil:
		return nil, KeyRecoverUnexpectedError
	}

	return key, nil
}

func (c *tpmKeyRecoverContext) DidUseKeyForDevice(devicePath string) {
	// TODO: Add the auth private key to the keyring in a format that can be decoded by GetActivationDataFromKernel later on
}

// KeyProtectorHandler provides an abstraction to facilitate unsealing a disk encryption key using an implementation specific
// keystore backend.
type KeyProtectorHandler interface {
	// DecodeToken implementations decode the provided token parameters which describe how to unseal a key in an implementation
	// specific way, and return a KeyRecoverContext
	DecodeToken(tokenParams map[string]interface{}) (KeyRecoverContext, error)

	// TODO: Add interface for decoding keyring entries to their correct go type (will be used by GetActivationDataFromKernel)
}

type tpmKeyProtectorHandler struct{}

func (p tpmKeyProtectorHandler) DecodeToken(tokenParams map[string]interface{}) (KeyRecoverContext, error) {
	s, ok := tokenParams[tpmSlotDataKey].(string)
	if !ok {
		return nil, KeyRecoverInvalidKeyDataError
	}

	r := base64.NewDecoder(base64.StdEncoding, bytes.NewReader([]byte(s)))
	data, err := decodeKeyData(r)
	if err != nil {
		return nil, KeyRecoverInvalidKeyDataError
	}

	return &tpmKeyRecoverContext{k: &SealedKeyObject{storage: sealedKeyObjectStorageReadOnly{}, data: data}}, nil
}

// keyProtectorHandlers is a map of known key protector handlers
// TODO: Provide an API to allow external KeyProtectorHandler implementations, and allow the TPM code to move in to a separate
// subpackage.
var keyProtectorHandlers = map[string]KeyProtectorHandler{"tpm": &tpmKeyProtectorHandler{}}

// KeyStore corresponds to a connection to a keystore, such as a TPM.
type KeyStore interface {
	Lock() error
}

type KeyStores []KeyStore

// RecoveryKeyUsageReason indicates the reason that a volume had to be activated with the fallback recovery key instead of the TPM
// sealed key.
// TODO: Replace RecoveryKeyUsageReason with an error code corresponding to why a key protector failed to recover a key, and expose
// this via GetActivationDataFromKernel which will contain a code for each keyslot that was tried (or a single error code in the
// ActivateVolumeWithTPMSealedKey case). We'll need to keep these definitions privately in order to decode a reason code for an
// activation from an older secboot version, and convert this to a new error code.
type RecoveryKeyUsageReason uint8

const (
	// RecoveryKeyUsageReasonUnexpectedError indicates that a volume had to be activated with the fallback recovery key because an
	// unexpected error was encountered during activation with the TPM sealed key.
	RecoveryKeyUsageReasonUnexpectedError RecoveryKeyUsageReason = iota + 1

	// RecoveryKeyUsageReasonRequested indicates that a volume was activated with the fallback recovery key via the
	// ActivateVolumeWithRecoveryKey API.
	RecoveryKeyUsageReasonRequested

	// RecoveryKeyUsageReasonTPMLockout indicates that a volume had to be activated with the fallback recovery key because the TPM is in
	// dictionary attack lockout mode.
	RecoveryKeyUsageReasonTPMLockout

	// RecoveryKeyUsageReasonTPMProvisioningError indicates that a volume had to be activated with the fallback recovery key because the
	// TPM is not correctly provisioned.
	RecoveryKeyUsageReasonTPMProvisioningError

	// RecoveryKeyUsageReasonInvalidKeyFile indicates that a volume had to be activated with the fallback recovery key because the TPM
	// sealed key file is invalid. Note that attempts to resolve this by creating a new file with SealKeyToTPM may indicate that the TPM
	// is also not correctly provisioned.
	RecoveryKeyUsageReasonInvalidKeyFile

	// RecoveryKeyUsageReasonPINFail indicates that a volume had to be activated with the fallback recovery key because the correct PIN
	// was not provided.
	RecoveryKeyUsageReasonPINFail
)

func activateWithRecoveryKey(volumeName, sourceDevicePath string, keyReader io.Reader, tries int, activateOptions []string) (RecoveryKey, error) {
	if tries == 0 {
		return RecoveryKey{}, errors.New("no recovery key tries permitted")
	}

	var key RecoveryKey
	var lastErr error

	for ; tries > 0; tries-- {
		lastErr = nil

		r := keyReader
		keyReader = nil

		passphrase, err := getPassword(sourceDevicePath, "recovery key", r)
		if err != nil {
			return RecoveryKey{}, xerrors.Errorf("cannot obtain recovery key: %w", err)
		}

		key, err = ParseRecoveryKey(passphrase)
		if err != nil {
			lastErr = xerrors.Errorf("cannot decode recovery key: %w", err)
			continue
		}

		err = luks2Activate(volumeName, sourceDevicePath, key[:], activateOptions)
		if err == nil {
			break
		}

		err = xerrors.Errorf("cannot activate volume: %w", err)
		if !isExitError(err) {
			return RecoveryKey{}, err
		}
		lastErr = err
	}

	return key, lastErr
}

var requiresPinErr = errors.New("no PIN tries permitted when a PIN is required")

type lockAccessError struct {
	err error
}

func (e lockAccessError) Error() string {
	return e.err.Error()
}

func (e lockAccessError) Unwrap() error {
	return e.err
}

func isLockAccessError(err error) bool {
	var e lockAccessError
	return xerrors.As(err, &e)
}

func activateWithTPMKey(tpm *TPMConnection, volumeName, sourceDevicePath string, k *SealedKeyObject, pinReader io.Reader, pinTries int, lock bool, activateOptions []string) error {
	var lockErr error
	key, err := func() ([]byte, error) {
		defer func() {
			if !lock {
				return
			}
			lockErr = LockAccessToSealedKeys(tpm)
		}()

		ctxt := &tpmKeyRecoverContext{k}
		switch {
		case pinTries == 0 && ctxt.PINRequired():
			return nil, requiresPinErr
		case pinTries == 0:
			pinTries = 1
		}

		var err error
		var key []byte

		for ; pinTries > 0; pinTries-- {
			var pin string
			if ctxt.PINRequired() {
				r := pinReader
				pinReader = nil
				pin, err = getPassword(sourceDevicePath, "PIN", r)
				if err != nil {
					return nil, xerrors.Errorf("cannot obtain PIN: %w", err)
				}
			}

			key, err = ctxt.Recover(KeyStores{tpm}, pin)
			if err != nil && (!isKeyRecoverError(err, KeyRecoverPINFailError) || !ctxt.PINRequired()) {
				break
			}
		}

		if err != nil {
			return nil, xerrors.Errorf("cannot unseal key: %w", err)
		}
		return key, nil
	}()

	switch {
	case lockErr != nil:
		return lockAccessError{err}
	case err != nil:
		return err
	}

	if err := luks2Activate(volumeName, sourceDevicePath, key, activateOptions); err != nil {
		return xerrors.Errorf("cannot activate volume: %w", err)
	}

	return nil
}

// ActivateWithTPMSealedKeyOptions provides options to ActivateVolumeWtthTPMSealedKey.
type ActivateWithTPMSealedKeyOptions struct {
	// PINTries specifies the maximum number of times that unsealing with a PIN should be attempted before failing with an error and
	// falling back to activating with the recovery key if RecoveryKeyTries is greater than zero. Setting this to zero disables unsealing
	// with a PIN - in this case, an error will be returned if the sealed key object indicates that a PIN has been set. Attempts to
	// unseal with a PIN will stop if the TPM enters dictionary attack lockout mode before this limit is reached.
	PINTries int

	// RecoveryKeyTries specifies the maximum number of times that activation with the fallback recovery key should be attempted
	// if activation with the TPM sealed key fails, before failing with an error. Setting this to zero will disable attempts to activate
	// with the fallback recovery key.
	RecoveryKeyTries int

	// ActivateOptions provides a mechanism to pass additional options to systemd-cryptsetup.
	ActivateOptions []string

	// LockSealedKeyAccess controls whether LockAccessToSealedKeys should be called after unsealing the TPM sealed key. It is called if
	// this is set to true, and not called if this is set to false.
	LockSealedKeyAccess bool
}

// ActivateVolumeWithTPMSealedKey attempts to activate the LUKS encrypted volume at sourceDevicePath and create a mapping with the
// name volumeName, using the TPM sealed key object at the specified keyPath. This makes use of systemd-cryptsetup.
//
// If the TPM sealed key object has a PIN defined, then this function will use systemd-ask-password to request it. If pinReader is not
// nil, then an attempt to read the PIN from this will be made instead by reading all characters until the first newline. The PINTries
// field of options defines how many attempts should be made to obtain the correct PIN before failing.
//
// The ActivateOptions field of options can be used to specify additional options to pass to systemd-cryptsetup.
//
// If the LockSealedKeyAccess field of options is true, then this function will call LockAccessToSealedKeys after unsealing the key
// and before activating the LUKS volume.
//
// If activation with the TPM sealed key object fails, this function will attempt to activate it with the fallback recovery key
// instead. The fallback recovery key will be requested using systemd-ask-password. The RecoveryKeyTries field of options specifies
// how many attempts should be made to activate the volume with the recovery key before failing. If this is set to 0, then no attempts
// will be made to activate the encrypted volume with the fallback recovery key. If activation with the recovery key is successful,
// the recovery key will be added to the root user keyring in the kernel with a description of the format
// "<argv[0]>:<volumeName>:reason=<reason>" where reason is an integer that describes the recovery reason - see the
// RecoveryKeyUsageReason type.
//
// If either the PINTries or RecoveryKeyTries fields of options are less than zero, an error will be returned. If the ActivateOptions
// field of options contains the "tries=" option, then an error will be returned. This option cannot be used with this function.
//
// If the LockSealedKeyAccess field of options is true and the call to LockAccessToSealedKeys fails, a LockAccessToSealedKeysError
// error will be returned. In this case, activation with either the TPM sealed key or the fallback recovery key will not be attempted.
//
// If activation with the TPM sealed key fails, a *ActivateWithTPMSealedKeyError error will be returned, even if the subsequent
// fallback recovery activation is successful. In this case, the RecoveryKeyUsageErr field of the returned error will be nil, and the
// TPMErr field will contain the original error. If activation with the fallback recovery key also fails, the RecoveryKeyUsageErr
// field of the returned error will also contain details of the error encountered during recovery key activation.
//
// If the volume is successfully activated, either with the TPM sealed key or the fallback recovery key, this function returns true.
// If it is not successfully activated, then this function returns false.
func ActivateVolumeWithTPMSealedKey(tpm *TPMConnection, volumeName, sourceDevicePath, keyPath string, pinReader io.Reader, options *ActivateWithTPMSealedKeyOptions) (bool, error) {
	if options.PINTries < 0 {
		return false, errors.New("invalid PINTries")
	}
	if options.RecoveryKeyTries < 0 {
		return false, errors.New("invalid RecoveryKeyTries")
	}

	k, err := ReadSealedKeyObjectFromFile(keyPath)
	if err != nil {
		err = xerrors.Errorf("cannot read sealed key object: %w", err)
		key, rErr := activateWithRecoveryKey(volumeName, sourceDevicePath, nil, options.RecoveryKeyTries, options.ActivateOptions)
		if rErr == nil {
			unix.AddKey("user", fmt.Sprintf("%s:%s:reason=%d", filepath.Base(os.Args[0]), volumeName, RecoveryKeyUsageReasonInvalidKeyFile), key[:], userKeyring)
		}
		return rErr == nil, &ActivateWithTPMSealedKeyError{err, rErr}
	}

	if err := activateWithTPMKey(tpm, volumeName, sourceDevicePath, k, pinReader, options.PINTries, options.LockSealedKeyAccess, options.ActivateOptions); err != nil {
		reason := RecoveryKeyUsageReasonUnexpectedError
		switch {
		case isLockAccessError(err):
			return false, LockAccessToSealedKeysError(err.Error())
		case isKeyRecoverError(err, KeyRecoverKeystoreTemporarilyUnavailableError):
			reason = RecoveryKeyUsageReasonTPMLockout
		case isKeyRecoverError(err, KeyRecoverKeystoreProvisioningError):
			reason = RecoveryKeyUsageReasonTPMProvisioningError
		case isKeyRecoverError(err, KeyRecoverInvalidKeyDataError):
			reason = RecoveryKeyUsageReasonInvalidKeyFile
		case xerrors.Is(err, requiresPinErr):
			reason = RecoveryKeyUsageReasonPINFail
		case isKeyRecoverError(err, KeyRecoverPINFailError):
			reason = RecoveryKeyUsageReasonPINFail
		case isExitError(err):
			// systemd-cryptsetup only provides 2 exit codes - success or fail - so we don't know the reason it failed yet. If activation
			// with the recovery key is successful, then it's safe to assume that it failed because the key unsealed from the TPM is incorrect.
			reason = RecoveryKeyUsageReasonInvalidKeyFile
		}
		key, rErr := activateWithRecoveryKey(volumeName, sourceDevicePath, nil, options.RecoveryKeyTries, options.ActivateOptions)
		if rErr == nil {
			unix.AddKey("user", fmt.Sprintf("%s:%s:reason=%d", filepath.Base(os.Args[0]), volumeName, reason), key[:], userKeyring)
		}
		return rErr == nil, &ActivateWithTPMSealedKeyError{err, rErr}
	}

	return true, nil
}

type keyUnsealContext struct {
	context KeyRecoverContext
	slotId  int
	err     error
}

func activateWithKeyProtectorContext(stores KeyStores, contexts []*keyUnsealContext, volumeName, sourceDevicePath string,
	pinReader io.Reader, pinTries int, lockStores bool, activateOptions []string) (bool, error) {
	var lockErr error
	key, c, err := func() ([]byte, *keyUnsealContext, error) {
		defer func() {
			if !lockStores {
				return
			}
			for _, s := range stores {
				lockErr = s.Lock()
			}
		}()

		recoverAndActivate := func(context KeyRecoverContext, pin string) ([]byte, error) {
			key, err := context.Recover(stores, pin)
			if err != nil {
				return nil, err
			}

			// If lockStores is true, defer activation until we know that locking was successful. In this case, return the key for
			// deferred activation. The downside of this is that the key we unsealed could be incorrect and activation might fail, but
			// we won't try any more keyslots. Unfortunately, there isn't a way to test that the recovered key is valid for the keyslot
			// with systemd-cryptsetup, and the cost of that might not even be desirable anyway. For most cases, there will be a single
			// master keyslot, so this isn't really an issue.
			if lockStores {
				return key, nil
			}

			// TODO: Specify keyslot
			if err := luks2Activate(volumeName, sourceDevicePath, key, activateOptions); err != nil {
				if isExitError(err) {
					return nil, KeyRecoverIncorrectKeyError
				}
				return nil, err
			}

			return nil, nil
		}

		hasSlotWithPIN := false

		// Try any tokens that don't require a PIN
		for _, c := range contexts {
			if c.err != nil {
				continue
			}

			if c.context.PINRequired() {
				hasSlotWithPIN = true
				continue
			}

			key, err := recoverAndActivate(c.context, "")
			if err == nil {
				return key, c, nil
			}

			c.err = err
		}

		// Try tokens that do require a PIN, if we have any
		for i := 0; i < pinTries && hasSlotWithPIN; i++ {
			r := pinReader
			pinReader = nil
			pin, err := getPassword(sourceDevicePath, "PIN", r)
			if err != nil {
				return nil, nil, xerrors.Errorf("cannot obtain PIN: %w", err)
			}

			for _, c := range contexts {
				if c.err != nil {
					continue
				}

				if !c.context.PINRequired() {
					continue
				}

				key, err := recoverAndActivate(c.context, pin)
				if err == nil {
					return key, c, nil
				}

				c.err = err
			}

			// XXX: Maybe add optional support for also testing the PIN against a plain passphrase based LUKS keyslot,
			//  for integration with conventional LUKS setups?
		}

		return nil, nil, nil
	}()

	switch {
	case lockErr != nil:
		return false, lockAccessError{err}
	case err != nil:
		return false, err
	case lockStores && c != nil:
		// Activation is deferred in this case
		c.err = luks2Activate(volumeName, sourceDevicePath, key, activateOptions)
		if isExitError(c.err) {
			c.err = KeyRecoverIncorrectKeyError
		}
	}

	if c != nil && c.err == nil {
		c.context.DidUseKeyForDevice(sourceDevicePath)
		return true, nil
	}
	return false, nil
}

type ActivateVolumeOptions struct {
	// PINTries specifies the maximum number of times that unsealing a keystore protected keyslot with a PIN should be attempted before
	// failing and falling back to activating with a recovery key if RecoveryKeyTries is greater than zero. Setting this to zero
	// disables unsealing with a PIN, in which case, if all keystore protected keyslots indicate a PIN is required, this will fall
	// back to activating with a recovery key if permitted. Note that a keystore implementation may limit PIN attempts to a number
	// less than this if it contains dictionary attack protection.
	PINTries int

	// RecoveryKeyTries specifies the maximum number of times that activation with the fallback recovery key should be attempted if
	// activation with a keystore protected key fails, before failing with an error. Setting this to zero will disable attempts to
	// activate with a fallback recovery key.
	RecoveryKeyTries int

	// ActivateOptions provides a mechanism to pass additional options to systemd-cryptsetup.
	ActivateOptions []string

	// LockKeyStores controls whether it should be possible to unseal any other keystore protected keys after the volume is activated
	// or if activation fails. If set to true, it will not be possible to unseal any other keystore protected keys.
	LockKeyStores bool
}

// ActivateLUKS2Volume attempts to activate the LUKS encrypted volume at sourceDevicePath and create a mapping with the supplied
// volumeName, by recovering keys that are protected by a keystore using metadata inside the LUKS header. This makes use of
// systemd-cryptsetup.
//
// Each keyslot that has metadata describing how to recover a key from a keystore using this package will be attempted. Keyslots that
// don't require a PIN will be attempted first. If none of these succeed, this function will try keyslots that indicate a PIN is
// required. It will use systemd-ask-password to request a PIN. If pinReader is not nil, then the PIN will be read from this on the
// first attempt by reading all characters until the first newline. The PINTries field of options defines how many attempts should be
// made to obtain the correct PIN before failing.
//
// Attempts to recover the key for each keyslot will be made using one of the supplied keystores. If no keystore is appropriate for a
// keyslot, then that keyslot will be ignored.
//
// The ActivateOptions field of options can be used to specify additional options to pass to systemd-cryptsetup. If this contains
// the "tries=" option, then an error will be returned. This option cannot be used with this function.
//
// If the LockKeyStores field of options is true, then this function will call the KeyStore.Lock method on each keystore before
// returning, regardless of whether the volume was activated successfully or not. If any of these calls fail, then a
// LockAccessToSealedKeysError error will be returned. The volume will not be activated unless all calls to KeyStore.Lock return
// without an error.
//
// If the LockKeyStores field of options is true, then this function will stop processing after the first keyslot it successfully
// recovers from a keystore. If the recovered key is incorrect, then activation will fail without attempting any more keyslots.
//
// If activation does not succeed with any keystore protected keys, this function will attempt to activate the volume with the
// fallback recovery key. The fallback recovery key will be requested using systemd-ask-password. The RecoveryKeyTries field of
// options specifies how many attempts should be made to activate the volume with the recovery key before failing. If this is set
// to 0, then no attempts will be made to activate the encrypted volume with the fallback recovery key.
//
// If the volume cannot be successfully activated, an error will be returned.
func ActivateLUKS2Volume(stores KeyStores, volumeName, sourceDevicePath string, pinReader io.Reader, options *ActivateVolumeOptions) error {
	if options.PINTries < 0 {
		// This is safer than returning an error particularly when LockKeyStores is set
		panic("invalid PINTries")
	}
	if options.RecoveryKeyTries < 0 {
		// This is safer than returning an error particularly when LockKeyStores is set
		panic("invalid RecoveryKeyTries")
	}

	// Decode LUKS2 metadata. Ensure that we lock keystores before returning if this fails.
	var lockErr error
	info, err := func() (*luks2.HdrInfo, error) {
		succeeded := false
		defer func() {
			if !options.LockKeyStores || succeeded {
				return
			}
			for _, s := range stores {
				lockErr = s.Lock()
			}
		}()

		release, err := luks2.AcquireLock(sourceDevicePath, luks2.LockModeShared)
		if err != nil {
			return nil, xerrors.Errorf("cannot acquire lock on device: %w", err)
		}
		defer release()

		info, err := luks2.DecodeHdr(sourceDevicePath)
		if err != nil {
			return nil, xerrors.Errorf("cannot decode metadata: %w", err)
		}
		return info, nil
	}()
	switch {
	case lockErr != nil:
		return LockAccessToSealedKeysError(err.Error())
	case err != nil:
		return err
	}

	// Iterate tokens and create unseal contexts for them
	var contexts []*keyUnsealContext
	hasRecoverySlot := false

	for _, v := range info.Metadata.Tokens {
		if v.Type != tokenType {
			// Not a slot managed by us.
			continue
		}
		if s := v.Params[slotTypeKey]; s == recoverySlotType {
			// Ignore recovery slot.
			hasRecoverySlot = true
			continue
		}
		if len(v.Keyslots) == 0 {
			// A token with no corresponding keyslots - shouldn't happen unless the metadata
			// has been modified outside of this package!
			continue
		}
		if _, ok := info.Metadata.Keyslots[v.Keyslots[0]]; !ok {
			// Keyslot associated with this token doesn't exist - shouldn't happen unless the
			// metadata has been modified outside of this package!
			continue
		}
		s, ok := v.Params[slotTypeKey].(string)
		if !ok {
			// Token is missing a valid "secboot-type" field.
			continue
		}
		handler, ok := keyProtectorHandlers[s]
		if !ok {
			// No handler for this type
			continue
		}
		context, err := handler.DecodeToken(v.Params)
		contexts = append(contexts, &keyUnsealContext{context, v.Keyslots[0], err})
	}

	activated, err := activateWithKeyProtectorContext(stores, contexts, volumeName, sourceDevicePath, pinReader, options.PINTries, options.LockKeyStores, options.ActivateOptions)
	switch {
	case isLockAccessError(err):
		// TODO: Maybe add a new error here?
		return LockAccessToSealedKeysError(err.Error())
	case err != nil:
		// This is an unexpected error. Most errors are tracked per keyslot and aren't returned here.
		return xerrors.Errorf("cannot activate volume with key protector: %w", err)
	case activated:
		// Activation was successful - nothing else to do!
		return nil
	}

	if !hasRecoverySlot {
		// XXX: Technically we could have multiple errors at this point, associated with each keyslot. How do we expose these via the API?
		return errors.New("cannot activate volume with key protector")
	}

	if _, err := activateWithRecoveryKey(volumeName, sourceDevicePath, nil, options.RecoveryKeyTries, options.ActivateOptions); err != nil {
		return errors.New("cannot activate volume with key protector or recovery key")
	}
	// TODO: If recovery succeeds, add the recovery key to the keyring with some JSON in the description with the error codes for each
	// keyslot so that they can be obtained by GetActivationDataFromKernel.
	return nil
}

// ActivateWithRecoveryKeyOptions provides options to ActivateVolumeWithRecoveryKey.
type ActivateWithRecoveryKeyOptions struct {
	// Tries specifies the maximum number of times that activation with the fallback recovery key should be attempted before failing
	// with an error.
	Tries int

	// ActivateOptions provides a mechanism to pass additional options to systemd-cryptsetup.
	ActivateOptions []string
}

// ActivateVolumeWithRecoveryKey attempts to activate the LUKS encrypted volume at sourceDevicePath and create a mapping with the
// name volumeName, using the fallback recovery key. This makes use of systemd-cryptsetup.
//
// This function will use systemd-ask-password to request the recovery key. If keyReader is not nil, then an attempt to read the key
// from this will be made instead by reading all characters until the first newline. The Tries field of options defines how many
// attempts should be made to activate the volume with the recovery key before failing.
//
// The ActivateOptions field of options can be used to specify additional options to pass to systemd-cryptsetup.
//
// If activation with the recovery key is successful, the recovery key will be added to the root user keyring in the kernel with a
// description of the format "<argv[0]>:<volumeName>:reason=2".
//
// If the Tries field of options is less than zero, an error will be returned. If the ActivateOptions field of options contains the
// "tries=" option, then an error will be returned. This option cannot be used with this function.
func ActivateVolumeWithRecoveryKey(volumeName, sourceDevicePath string, keyReader io.Reader, options *ActivateWithRecoveryKeyOptions) error {
	if options.Tries < 0 {
		return errors.New("invalid Tries")
	}

	key, err := activateWithRecoveryKey(volumeName, sourceDevicePath, keyReader, options.Tries, options.ActivateOptions)
	if err != nil {
		return err
	}
	unix.AddKey("user", fmt.Sprintf("%s:%s:reason=%d", filepath.Base(os.Args[0]), volumeName, RecoveryKeyUsageReasonRequested), key[:], userKeyring)
	return nil
}

func makeTokenForKeyslot(slotType string, slot int) *luks2.Token {
	return &luks2.Token{Type: tokenType, Keyslots: []int{slot}, Params: map[string]interface{}{slotTypeKey: slotType}}
}

// InitializeLUKS2Container will initialize the partition at the specified devicePath as a new LUKS2 container. This can only
// be called on a partition that isn't mapped. The label for the new LUKS2 container is provided via the label argument.
//
// The initial master key used for unlocking the container is provided via the key argument, and must be a cryptographically secure
// 64-byte random number. The key should be protected by a hardware backed keystore, such as a TPM by using SealKeyToTPM. Note that
// "master key" in this context refers to the main key used to activate the volume, and is not the same as the LUKS volume key
// although they must be the same size.
//
// The container will be configured to encrypt data with AES-256 and XTS block cipher mode.
//
// On failure, this will return an error containing the output of the cryptsetup command.
//
// WARNING: This function is destructive. Calling this on an existing LUKS container will make the data contained inside of it
// irretrievable.
func InitializeLUKS2Container(devicePath, label string, key []byte) error {
	releaseLock, err := luks2.AcquireLock(devicePath, luks2.LockModeExclusive)
	if err != nil {
		return xerrors.Errorf("cannot acquire lock: %w", err)
	}
	defer releaseLock()

	if err := luks2.Format(devicePath, label, key, &luks2.KDFOptions{Master: true}); err != nil {
		return xerrors.Errorf("cannot format device: %w", err)
	}

	if err := luks2.SetKeyslotPriority(devicePath, 0, "prefer"); err != nil {
		return xerrors.Errorf("cannot set keyslot priority: %w", err)
	}

	if err := luks2.ImportToken(devicePath, makeTokenForKeyslot(masterSlotType, 0)); err != nil {
		return xerrors.Errorf("cannot add token: %w", err)
	}

	return nil
}

func setLUKS2ContainerKey(devicePath string, existingKey, newKey []byte, slotType string, kdf *luks2.KDFOptions) (int, error) {
	startInfo, err := luks2.DecodeHdr(devicePath)
	if err != nil {
		return 0, xerrors.Errorf("cannot decode LUKS2 header: %w", err)
	}

	oldTokenId := -1
	for k, v := range startInfo.Metadata.Tokens {
		if v.Type != tokenType {
			continue
		}
		if s := v.Params[slotTypeKey]; s == slotType {
			oldTokenId = int(k)
			break
		}
	}

	if err := luks2.AddKey(devicePath, existingKey, newKey, kdf); err != nil {
		return 0, xerrors.Errorf("cannot add new keyslot: %w", err)
	}

	updatedInfo, err := luks2.DecodeHdr(devicePath)
	if err != nil {
		return 0, xerrors.Errorf("cannot decode updated LUKS2 header: %w", err)
	}

	newSlotId := -1
	for s := range updatedInfo.Metadata.Keyslots {
		if _, ok := startInfo.Metadata.Keyslots[s]; !ok {
			newSlotId = int(s)
			break
		}
	}

	if newSlotId == -1 {
		return 0, errors.New("cannot determine new keyslot ID")
	}

	if err := luks2.ImportToken(devicePath, makeTokenForKeyslot(slotType, newSlotId)); err != nil {
		return 0, xerrors.Errorf("cannot add new token: %w", err)
	}

	if oldTokenId == -1 {
		return newSlotId, nil
	}

	if len(startInfo.Metadata.Tokens[oldTokenId].Keyslots) > 0 {
		if err := luks2.KillSlot(devicePath, int(startInfo.Metadata.Tokens[oldTokenId].Keyslots[0]), newKey); err != nil {
			return 0, xerrors.Errorf("cannot delete old keyslot: %w", err)
		}
	}

	if err := luks2.RemoveToken(devicePath, oldTokenId); err != nil {
		return 0, xerrors.Errorf("cannot delete old token: %w", err)
	}

	return newSlotId, nil
}

// SetLUKS2ContainerRecoveryKey sets the fallback recovery key on an existing LUKS2 container created with InitializeLUKS2Container.
// The recovery key is intended to be provided manually as a fallback mechanism that operates independently of any hardware backed
// keystore in the event that the key normally used for unlocking the container cannot be recovered. The devicePath argument specifies
// the device that contains the LUKS2 container. An existing key or passphrase for the container must be provided via the existingKey
// argument.
//
// The recovery key is provided via the recoveryKey argument and must be a cryptographically secure 16-byte random number.
//
// If the container already has a recovery key defined, then this function will delete the old recovery key once the new one has been
// set.
func SetLUKS2ContainerRecoveryKey(devicePath string, existingKey []byte, recoveryKey RecoveryKey) error {
	releaseLock, err := luks2.AcquireLock(devicePath, luks2.LockModeExclusive)
	if err != nil {
		return xerrors.Errorf("cannot acquire lock: %w", err)
	}
	defer releaseLock()

	// Use a KDF with an increased cost for the recovery key.
	_, err = setLUKS2ContainerKey(devicePath, existingKey, recoveryKey[:], recoverySlotType, &luks2.KDFOptions{IterTime: 5 * time.Second})
	return err
}

// SetLUKS2ContainerMasterKey sets the master key that is normally used for unlocking the LUKS2 container at devicePath. This
// function is intended to be used after the container has had to be unlocked with the recovery key because the original master
// key could not be recovered from the hardware backed keystore that is protecting it. It can also be used to set the master key
// for a container that is normally unlocked with a passphrase. An existing key or passphrase for the container must be provided
// via the existingKey argument.
//
// The new key is provided via the key argument and must be a cryptographically secure 64-byte random number.
//
// If the container already has a master key defined, then this function will delete the old master key once the new one has been set.
func SetLUKS2ContainerMasterKey(devicePath string, existingKey, newKey []byte) error {
	releaseLock, err := luks2.AcquireLock(devicePath, luks2.LockModeExclusive)
	if err != nil {
		return xerrors.Errorf("cannot acquire lock: %w", err)
	}
	defer releaseLock()

	slotId, err := setLUKS2ContainerKey(devicePath, existingKey, newKey, masterSlotType, &luks2.KDFOptions{Master: true})
	if err != nil {
		return err
	}

	if err := luks2.SetKeyslotPriority(devicePath, slotId, "prefer"); err != nil {
		return xerrors.Errorf("cannot set priority of new keyslot: %w", err)
	}

	return nil
}

// SealLUKS2MasterKeyToTPM seals the supplied master key to the storage hierarchy of the TPM. The supplied key must match any existing
// master key that wasn't added by SetLUKS2ContainerRecovery key for the specified device. The sealed key object and associated
// metadata that is required during early boot in order to unseal the key again and unlock the encrypted volume is written to a LUKS2
// token for the corresponding keyslot on the specified device. Additional data that is required in order to update the authorization
// policy for the sealed key is written to a file at the path specified by policyUpdatePath. This file must live inside the encrypted
// volume.
//
// This function requires knowledge of the authorization value for the storage hierarchy, which must be provided by calling
// TPMConnection.OwnerHandleContext().SetAuthValue() prior to calling this function. If the provided authorization value is incorrect,
// a AuthFailError error will be returned.
//
// If the TPM is not correctly provisioned, a ErrTPMProvisioning error will be returned. In this case, ProvisionTPM must be called
// before proceeding.
//
// This function expects there to be no file at the specified path. If the path references a file that already exists, a wrapped
// *os.PathError error will be returned with an underlying error of syscall.EEXIST. A wrapped *os.PathError error will be returned if
// the file cannot be created and opened for writing.
//
// This function will create a NV index at the handle specified by the PINHandle field of the params argument. If the handle is already
// in use, a TPMResourceExistsError error will be returned. In this case, the caller will need to either choose a different handle or
// undefine the existing one. The handle must be a valid NV index handle (MSO == 0x01), and the choice of handle should take in to
// consideration the reserved indices from the "Registry of reserved TPM 2.0 handles and localities" specification. It is recommended
// that the handle is in the block reserved for owner objects (0x01800000 - 0x01bfffff).
//
// The key will be protected with a PCR policy computed from the PCRProtectionProfile supplied via the PCRProfile field of the params
// argument.
//
// If an existing keyslot is protected by a TPM sealed key and it is not the keyslot that is associated with the supplied key, this
// function will remove it.
func SealLUKS2MasterKeyToTPM(tpm *TPMConnection, devicePath string, key []byte, policyUpdatePath string, params *KeyCreationParams) error {
	releaseLock, err := luks2.AcquireLock(devicePath, luks2.LockModeExclusive)
	if err != nil {
		return xerrors.Errorf("cannot acquire lock: %w", err)
	}
	defer releaseLock()

	info, err := luks2.DecodeHdr(devicePath)
	if err != nil {
		return xerrors.Errorf("cannot decode LUKS2 header: %w", err)
	}

	targetTokenId := -1
	for k, v := range info.Metadata.Tokens {
		if v.Type != tokenType {
			continue
		}
		if s := v.Params[slotTypeKey]; s == recoverySlotType {
			continue
		}
		if len(v.Keyslots) > 0 {
			if err := luks2.TestPassphrase(devicePath, v.Keyslots[0], key); err == nil {
				targetTokenId = int(k)
				break
			}
		}
	}

	if targetTokenId == -1 {
		return errors.New("cannot find matching master key")
	}

	existingTpmTokenId := -1
	for k, v := range info.Metadata.Tokens {
		if v.Type != tokenType {
			continue
		}
		if s := v.Params[slotTypeKey]; s == tpmSlotType {
			existingTpmTokenId = int(k)
			break
		}
	}

	var sealedKeyObject bytes.Buffer

	succeeded := true
	var policyUpdateFile *os.File
	if policyUpdatePath != "" {
		var err error
		policyUpdateFile, err = os.OpenFile(policyUpdatePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return xerrors.Errorf("cannot create private data file: %w", err)
		}
		defer func() {
			policyUpdateFile.Close()
			if succeeded {
				return
			}
			os.Remove(policyUpdatePath)
		}()
	}

	if err := sealKeyToTPMCommon(tpm, key, &sealedKeyObject, policyUpdateFile, params); err != nil {
		return err
	}

	token := makeTokenForKeyslot(tpmSlotType, info.Metadata.Tokens[targetTokenId].Keyslots[0])
	token.Params[tpmSlotDataKey] = sealedKeyObject.Bytes()

	if err := luks2.ImportToken(devicePath, token); err != nil {
		return xerrors.Errorf("cannot import new token: %w", err)
	}

	if err := luks2.RemoveToken(devicePath, targetTokenId); err != nil {
		return xerrors.Errorf("cannot delete old token: %w", err)
	}

	if existingTpmTokenId != -1 && existingTpmTokenId != targetTokenId {
		if err := luks2.RemoveToken(devicePath, existingTpmTokenId); err != nil {
			return xerrors.Errorf("cannot delete old token: %w", err)
		}

		if len(info.Metadata.Tokens[existingTpmTokenId].Keyslots) > 0 {
			if err := luks2.KillSlot(devicePath, info.Metadata.Tokens[existingTpmTokenId].Keyslots[0], key); err != nil {
				return xerrors.Errorf("cannot delete old TPM key slot: %w", err)
			}
		}
	}

	succeeded = true
	return nil
}

type sealedKeyObjectStorageLUKS2 string

func (s sealedKeyObjectStorageLUKS2) commitAtomic(data *keyData) error {
	release, err := luks2.AcquireLock(string(s), luks2.LockModeExclusive)
	if err != nil {
		return xerrors.Errorf("cannot acquire lock: %w", err)
	}
	defer release()

	info, err := luks2.DecodeHdr(string(s))
	if err != nil {
		return xerrors.Errorf("cannot decode header: %w", err)
	}

	existingTokenId := -1
	for k, v := range info.Metadata.Tokens {
		if v.Type != tokenType {
			continue
		}
		if s := v.Params[slotTypeKey]; s == tpmSlotType {
			existingTokenId = int(k)
			break
		}
	}

	if existingTokenId == -1 {
		return errors.New("existing token was deleted")
	}
	if len(info.Metadata.Tokens[existingTokenId].Keyslots) == 0 {
		return errors.New("existing token is not associated with a keyslot")
	}

	var buf bytes.Buffer
	if err := data.write(&buf); err != nil {
		return xerrors.Errorf("cannot encode data: %w", err)
	}

	token := makeTokenForKeyslot(tpmSlotType, info.Metadata.Tokens[existingTokenId].Keyslots[0])
	token.Params[tpmSlotDataKey] = buf.Bytes()

	if err := luks2.ImportToken(string(s), token); err != nil {
		return xerrors.Errorf("cannot import new token: %w", err)
	}

	if err := luks2.RemoveToken(string(s), existingTokenId); err != nil {
		return xerrors.Errorf("cannot delete old token: %w", err)
	}

	return nil
}

// ReadSealedKeyObjectFromLUKS2 loads a sealed key data object from the specified LUKS2 container. If the container cannot be
// opened, a wrapped *os.PathError error is returned. If the key data cannot be found or deserialized successfully, a
// InvalidKeyFileError error will be returned.
func ReadSealedKeyObjectFromLUKS2(devicePath string) (*SealedKeyObject, error) {
	release, err := luks2.AcquireLock(devicePath, luks2.LockModeShared)
	if err != nil {
		return nil, xerrors.Errorf("cannot acquire lock: %w", err)
	}
	defer release()

	info, err := luks2.DecodeHdr(devicePath)
	if err != nil {
		return nil, xerrors.Errorf("cannot decode header: %w", err)
	}

	var r io.Reader

	for _, v := range info.Metadata.Tokens {
		if v.Type != tokenType {
			continue
		}
		if s := v.Params[slotTypeKey]; s != tpmSlotType {
			continue
		}
		s, ok := v.Params[tpmSlotDataKey].(string)
		if ok {
			r = base64.NewDecoder(base64.StdEncoding, bytes.NewReader([]byte(s)))
			break
		}
	}

	if r == nil {
		return nil, errors.New("no valid TPM token found")
	}

	data, err := decodeKeyData(r)
	if err != nil {
		return nil, InvalidKeyFileError{err.Error()}
	}

	return &SealedKeyObject{storage: sealedKeyObjectStorageLUKS2(devicePath), data: data}, nil
}
