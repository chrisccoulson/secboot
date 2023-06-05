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

package efi_test

import (
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/testutil"
)

func Test(t *testing.T) { TestingT(t) }

type mockPcrProfileContext struct {
	alg      tpm2.HashAlgorithmId
	handlers ImageLoadHandlers
}

func (c *mockPcrProfileContext) PCRAlg() tpm2.HashAlgorithmId {
	return c.alg
}

func (*mockPcrProfileContext) Flags() PcrProfileFlags {
	return 0
}

func (c *mockPcrProfileContext) ImageLoadHandlers() ImageLoadHandlers {
	return c.handlers
}

type mockPeImageHandle struct {
	source Image
}

func (*mockPeImageHandle) Close() error                                { return nil }
func (h *mockPeImageHandle) Source() Image                             { return h.source }
func (*mockPeImageHandle) OpenSection(name string) *io.SectionReader   { return nil }
func (*mockPeImageHandle) HasSection(name string) bool                 { return false }
func (*mockPeImageHandle) HasSbatSection() bool                        { return false }
func (*mockPeImageHandle) SbatComponents() ([]SbatComponent, error)    { return nil, nil }
func (*mockPeImageHandle) ImageDigest(alg crypto.Hash) ([]byte, error) { return nil, nil }
func (*mockPeImageHandle) SecureBootSignatures() ([]*efi.WinCertificateAuthenticode, error) {
	return nil, nil
}

type mockImage struct {
	a int
}

func (i *mockImage) String() string           { return fmt.Sprintf("%p", i) }
func (*mockImage) Open() (ImageReader, error) { return nil, errors.New("not implemented") }

type mockImageLoadHandlers map[Image]ImageLoadHandler

func (h mockImageLoadHandlers) NewOrExisting(image PeImageHandle) (ImageLoadHandler, error) {
	handler, exists := h[image.Source()]
	if !exists {
		return nil, errors.New("no handler")
	}
	return handler, nil
}

type mockLoadHandler struct {
	startActions []func(PcrBranchContext) error
	loadActions  []func(PcrBranchContext) error
}

type mockLoadHandlerAction func(*mockLoadHandler)

func newMockLoadHandler(actions ...mockLoadHandlerAction) *mockLoadHandler {
	out := new(mockLoadHandler)
	for _, action := range actions {
		action(out)
	}
	return out
}

func (h *mockLoadHandler) withExtendPCROnImageStart(pcr int, digest tpm2.Digest) *mockLoadHandler {
	h.startActions = append(h.startActions, func(ctx PcrBranchContext) error {
		ctx.ExtendPCR(pcr, digest)
		return nil
	})
	return h
}

func (h *mockLoadHandler) withMeasureVariableOnImageStart(pcr int, guid efi.GUID, name string) *mockLoadHandler {
	h.startActions = append(h.startActions, func(ctx PcrBranchContext) error {
		data, _, err := ctx.Vars().ReadVar(name, guid)
		switch {
		case err == efi.ErrVarNotExist:
		case err != nil:
			return err
		}
		ctx.MeasureVariable(pcr, guid, name, data)
		return nil
	})
	return h
}

func (h *mockLoadHandler) withCheckParamsOnImageStarts(c *C, params ...*LoadParams) *mockLoadHandler {
	h.startActions = append(h.startActions, func(ctx PcrBranchContext) error {
		c.Assert(params, Not(HasLen), 0)
		c.Check(ctx.Params(), DeepEquals, params[0])
		params = params[1:]
		return nil
	})
	return h
}

func (h *mockLoadHandler) withCheckVarOnImageStarts(c *C, name string, guid efi.GUID, data ...[]byte) *mockLoadHandler {
	h.startActions = append(h.startActions, func(ctx PcrBranchContext) error {
		c.Assert(data, Not(HasLen), 0)
		d, _, err := ctx.Vars().ReadVar(name, guid)
		c.Check(err, IsNil)
		c.Check(d, DeepEquals, data[0])
		data = data[1:]
		return nil
	})
	return h
}

func (h *mockLoadHandler) withSetVarOnImageStart(name string, guid efi.GUID, attrs efi.VariableAttributes, data []byte) *mockLoadHandler {
	h.startActions = append(h.startActions, func(ctx PcrBranchContext) error {
		return ctx.Vars().WriteVar(name, guid, attrs, data)
	})
	return h
}

func (h *mockLoadHandler) withCheckFwHasVerificationEventOnImageStart(c *C, digest tpm2.Digest, exists bool) *mockLoadHandler {
	h.startActions = append(h.startActions, func(ctx PcrBranchContext) error {
		var checker Checker
		if exists {
			checker = testutil.IsTrue
		} else {
			checker = testutil.IsFalse
		}
		c.Check(ctx.FwContext().HasVerificationEvent(digest), checker)
		return nil
	})
	return h
}

func (h *mockLoadHandler) withAppendFwVerificationEventOnImageStart(c *C, digest tpm2.Digest) *mockLoadHandler {
	h.startActions = append(h.startActions, func(ctx PcrBranchContext) error {
		ctx.FwContext().AppendVerificationEvent(digest)
		return nil
	})
	return h
}

func (h *mockLoadHandler) withCheckShimHasVerificationEventOnImageStart(c *C, digest tpm2.Digest, exists bool) *mockLoadHandler {
	h.startActions = append(h.startActions, func(ctx PcrBranchContext) error {
		var checker Checker
		if exists {
			checker = testutil.IsTrue
		} else {
			checker = testutil.IsFalse
		}
		c.Check(ctx.ShimContext().HasVerificationEvent(digest), checker)
		return nil
	})
	return h
}

func (h *mockLoadHandler) withAppendShimVerificationEventOnImageStart(c *C, digest tpm2.Digest) *mockLoadHandler {
	h.startActions = append(h.startActions, func(ctx PcrBranchContext) error {
		ctx.ShimContext().AppendVerificationEvent(digest)
		return nil
	})
	return h
}

func (h *mockLoadHandler) withExtendPCROnImageLoads(pcr int, digests ...tpm2.Digest) *mockLoadHandler {
	h.loadActions = append(h.loadActions, func(ctx PcrBranchContext) error {
		if len(digests) == 0 {
			return errors.New("no digests")
		}
		digest := digests[0]
		digests = digests[1:]
		ctx.ExtendPCR(pcr, digest)
		return nil
	})
	return h
}

func (h *mockLoadHandler) MeasureImageStart(ctx PcrBranchContext) error {
	for _, action := range h.startActions {
		if err := action(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (h *mockLoadHandler) MeasureImageLoad(ctx PcrBranchContext, image PeImageHandle) (ImageLoadHandler, error) {
	for _, action := range h.loadActions {
		if err := action(ctx); err != nil {
			return nil, err
		}
	}
	return NewOrExistingImageLoadHandler(ctx, image)
}

type mockEFIVar struct {
	data  []byte
	attrs efi.VariableAttributes
}

type mockEFIEnvironment struct {
	vars map[efi.VariableDescriptor]*mockEFIVar
	log  *tcglog.Log
}

func newMockEFIEnvironment(vars map[efi.VariableDescriptor]*mockEFIVar, log *tcglog.Log) *mockEFIEnvironment {
	return &mockEFIEnvironment{vars: vars, log: log}
}

func newMockEFIEnvironmentFromFiles(c *C, efivarsDir, logFile string) *mockEFIEnvironment {
	vars := make(map[efi.VariableDescriptor]*mockEFIVar)
	if efivarsDir != "" {
		dir, err := os.Open(efivarsDir)
		c.Assert(err, IsNil)
		defer dir.Close()

		entries, err := dir.Readdir(-1)
		c.Assert(err, IsNil)

		r := regexp.MustCompile(`^([[:alnum:]]+)-([[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12})$`)

		for _, entry := range entries {
			m := r.FindStringSubmatch(entry.Name())
			if len(m) == 0 {
				continue
			}

			name := m[1]
			guid, err := efi.DecodeGUIDString(m[2])
			c.Assert(err, IsNil)

			data, err := ioutil.ReadFile(filepath.Join(efivarsDir, entry.Name()))
			c.Assert(err, IsNil)
			if len(data) < 4 {
				c.Fatal(entry.Name(), "contents too short")
			}

			vars[efi.VariableDescriptor{Name: name, GUID: guid}] = &mockEFIVar{
				data:  data[4:],
				attrs: efi.VariableAttributes(binary.LittleEndian.Uint32(data))}
		}
	}

	var log *tcglog.Log
	if logFile != "" {
		f, err := os.Open(logFile)
		c.Assert(err, IsNil)
		defer f.Close()

		log, err = tcglog.ReadLog(f, &tcglog.LogOptions{})
		c.Assert(err, IsNil)
	}
	return newMockEFIEnvironment(vars, log)
}

func (e *mockEFIEnvironment) ReadVar(name string, guid efi.GUID) ([]byte, efi.VariableAttributes, error) {
	if e.vars == nil {
		return nil, 0, efi.ErrVarNotExist
	}
	v, found := e.vars[efi.VariableDescriptor{Name: name, GUID: guid}]
	if !found {
		return nil, 0, efi.ErrVarNotExist
	}
	return v.data, v.attrs, nil
}

func (e *mockEFIEnvironment) ReadEventLog() (*tcglog.Log, error) {
	return e.log, nil
}
