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

package internal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/linux"
	"github.com/canonical/tcglog-parser"
)

var (
	linuxDefaultTPM2Device              = linux.DefaultTPM2Device
	linuxRawDeviceResourceManagedDevice = (*linux.RawDevice).ResourceManagedDevice

	eventLogPath = "/sys/kernel/security/tpm0/binary_bios_measurements" // Path of the TCG event log for the default TPM, in binary form
	sysfsPath    = "/sys"
)

type defaultEnvImpl struct{}

// VarContext implements [efi.HostEnvironment.VarContext].
func (defaultEnvImpl) VarContext() context.Context {
	return efi.DefaultVarContext
}

// ReadEventLog implements [efi.HostEnvironment.ReadEventLog].
func (defaultEnvImpl) ReadEventLog() (*tcglog.Log, error) {
	f, err := os.Open(eventLogPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return tcglog.ReadLog(f, &tcglog.LogOptions{})
}

// TPMDevice implements [preinstall.HostEnvironment.TPMDevice].
func (defaultEnvImpl) TPMDevice() (tpm2.TPMDevice, error) {
	device, err := linuxDefaultTPM2Device()
	switch {
	case errors.Is(err, linux.ErrNoTPMDevices) || errors.Is(err, linux.ErrDefaultNotTPM2Device):
		return nil, ErrNoTPM2Device
	case err != nil:
		return nil, err
	}

	rmDevice, err := linuxRawDeviceResourceManagedDevice(device)
	switch {
	case errors.Is(err, linux.ErrNoResourceManagedDevice):
		// Return the raw device. This can only be open once, so can block and may block other users.
		return device, nil
	case err != nil:
		return nil, err
	default:
		// Return the resource managed device. There is no limit as to how may of these can be opened,
		// although note that they can't be opened if the raw device is opened so this can still block
		// if something else has the raw device open and might block other raw device users.
		return rmDevice, nil
	}
}

// DetectVirtMode implements [preinstall.HostEnvironment.DetectVirtMode].
func (defaultEnvImpl) DetectVirtMode(mode DetectVirtMode) (string, error) {
	var extraArgs []string
	switch mode {
	case DetectVirtModeAll:
		// no extra args
	case DetectVirtModeContainer:
		extraArgs = []string{"--container"}
	case DetectVirtModeVM:
		extraArgs = []string{"--vm"}
	default:
		panic("not reached")
	}

	output, err := exec.Command("systemd-detect-virt", extraArgs...).Output()
	virt := string(bytes.TrimSpace(output)) // The stdout is newline terminated
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok && virt == VirtModeNone {
			// systemd-detect-virt returns non zero exit code if no virtualization is detected
			return virt, nil
		}
		return "", err
	}
	return virt, nil
}

type defaultEnvSysfsDevice struct {
	name      string
	path      string
	subsystem string
}

// Name implements [SysfsDevice.Name].
func (d *defaultEnvSysfsDevice) Name() string {
	return d.name
}

// Path implements [SysfsDevice.Path].
func (d *defaultEnvSysfsDevice) Path() string {
	return d.path
}

// Subsystem implements [SysfsDevice.Subsystem].
func (d *defaultEnvSysfsDevice) Subsystem() string {
	return d.subsystem
}

// AttributeReader implements [SysfsDevice.AttributeReader].
func (d *defaultEnvSysfsDevice) AttributeReader(attr string) (rc io.ReadCloser, err error) {
	if attr == "uevent" {
		return nil, ErrNoDeviceAttribute
	}

	f, err := os.Open(filepath.Join(d.path, attr))
	switch {
	case os.IsNotExist(err):
		return nil, ErrNoDeviceAttribute
	case err != nil:
		return nil, err
	}
	defer func() {
		if err == nil {
			return
		}
		f.Close()
	}()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, ErrNoDeviceAttribute
	}

	return f, nil
}

// DeviceForClass implements [preinstall.HostEnvironment.DevicesForClass].
func (defaultEnvImpl) DevicesForClass(class string) ([]SysfsDevice, error) {
	classPath := filepath.Join(sysfsPath, "class", class)
	f, err := os.Open(classPath)
	switch {
	case os.IsNotExist(err):
		// it's ok to have no devices for the specified class
		return nil, nil
	case err != nil:
		return nil, err
	}
	defer f.Close()

	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}

	var out []SysfsDevice
	for _, entry := range entries {
		path, err := filepath.EvalSymlinks(filepath.Join(classPath, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("cannot resolve path for %s: %w", entry.Name(), err)
		}
		subsystem, err := filepath.EvalSymlinks(filepath.Join(path, "subsystem"))
		if err != nil {
			return nil, fmt.Errorf("cannot resolve subsystem for %s: %w", entry.Name(), err)
		}
		out = append(out, &defaultEnvSysfsDevice{
			name:      entry.Name(),
			path:      path,
			subsystem: filepath.Base(subsystem),
		})
	}
	return out, nil
}

// DefaultEnv corresponds to the environment associated with the host
// machine.
var DefaultEnv = defaultEnvImpl{}
