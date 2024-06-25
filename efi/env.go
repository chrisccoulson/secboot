// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019-2023 Canonical Ltd
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
	"context"
	"crypto"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"sort"

	efi "github.com/canonical/go-efilib"
	"github.com/snapcore/secboot/efi/internal"
	"golang.org/x/xerrors"
)

// HostEnvironment is an interface that abstracts out an EFI environment, so that
// consumers of the API can provide a custom mechanism to read EFI variables or parse
// the TCG event log.
type HostEnvironment = internal.HostEnvironmentEFI

type hostEnvironmentOption struct {
	HostEnvironment
}

// WithHostEnvironment overrides the EFI host environment for a PCR profile with
// the supplied environment. This is useful when generating a profile for a device
// other than the current host.
func WithHostEnvironment(env HostEnvironment) PCRProfileOption {
	return &hostEnvironmentOption{HostEnvironment: env}
}

func (o *hostEnvironmentOption) ApplyOptionTo(visitor internal.PCRProfileOptionVisitor) error {
	visitor.SetEnvironment(o.HostEnvironment)
	return nil
}

// varReader is an interface that provides access to reading EFI variables during
// profile generation.
type varReader interface {
	// ReadVar reads the specified EFI variable
	ReadVar(name string, guid efi.GUID) ([]byte, efi.VariableAttributes, error)
}

// varReadWriter is an interface for reading and mock updating EFI variables during
// profile generation.
type varReadWriter interface {
	varReader

	// WriteVar updates the specified EFI variable.
	WriteVar(name string, guid efi.GUID, attrs efi.VariableAttributes, data []byte) error
}

// varUpdate is the sequence of updates generated by a profile branch, associated with
// a varBranch.
type varUpdate struct {
	previous *varUpdate             // link to the previous update
	name     efi.VariableDescriptor // the variable name associated with the update
	attrs    efi.VariableAttributes // the corresponding attributes
	data     []byte                 // the updated variable data
}

type varBranchRegisterUpdatesFn func(*varUpdate) error

// varBranch corresponds to a EFI variable set associated with a profile branch,
// consisting of an initial starting environment and a sequence of updates that have been
// added during profile generation. Each profile generation loop starts with one of these
// without any updates. Branches in a profile inherit a copy of this from the parent branch
// and may make modifications to EFI variables (eg, applying a SBAT update) which may affect
// other branches - in this case, the profile generation may be re-executed multiple times
// with different initial sets as a result of these updates. These starting sets are
// computed and tracked by the assocated variableSetCollector.
type varBranch struct {
	initial         varReader  // the initial starting environment
	updates         *varUpdate // the updates applied by the associated branch
	registerUpdates varBranchRegisterUpdatesFn
}

// ReadVar implements varReader.ReadVar and internal.VariableSet.ReadVar.
func (s *varBranch) ReadVar(name string, guid efi.GUID) ([]byte, efi.VariableAttributes, error) {
	update := s.updates
	for ; update != nil; update = update.previous {
		desc := efi.VariableDescriptor{Name: name, GUID: guid}
		if update.name == desc {
			return update.data, update.attrs, nil
		}
	}
	return s.initial.ReadVar(name, guid)
}

// WriteVar implements varReadWriter.WriteVar and internal.VariableSet.WriteVar.
// Calling this creates and registers an update which may create a new initial
// starting variable set for another profile generation loop.
func (s *varBranch) WriteVar(name string, guid efi.GUID, attrs efi.VariableAttributes, data []byte) error {
	orig, _, err := s.ReadVar(name, guid)
	switch {
	case err == efi.ErrVarNotExist:
		// ok
	case err != nil:
		return err
	}

	if attrs&efi.AttributeAppendWrite != 0 {
		data = append(orig, data...)
	}

	s.updates = &varUpdate{
		previous: s.updates,
		name:     efi.VariableDescriptor{Name: name, GUID: guid},
		attrs:    attrs &^ efi.AttributeAppendWrite,
		data:     data}
	return s.registerUpdates(s.updates)
}

// Clone implements internal.VariableSet.Clone. It returns an exact copy of this
// varBranch to enable callers to WriteVar to create multiple branches with different
// write sequences.
func (s *varBranch) Clone() internal.VariableSet {
	clone := *s
	return &clone
}

// initialVarReaderKey is a SHA1 used to uniquely identify the contents of a initialVarReader.
// This is to ensure that we don't generate multiple profile branches with the same
// starting state.
type initialVarReaderKey [sha1.Size]byte

type varContents struct {
	attrs efi.VariableAttributes
	data  []byte
}

// initialVarReader provides the initial starting set for each profile generation branch.
// It consists of the host environment and updates that have been generated by previous
// iterations of the profile generation.
type initialVarReader struct {
	varsCtx   context.Context
	overrides map[efi.VariableDescriptor]varContents
}

// ReadVar implements varReader.ReadVar
func (r *initialVarReader) ReadVar(name string, guid efi.GUID) ([]byte, efi.VariableAttributes, error) {
	override, exists := r.overrides[efi.VariableDescriptor{Name: name, GUID: guid}]
	if exists {
		return override.data, override.attrs, nil
	}
	return efi.ReadVariable(r.varsCtx, name, guid)
}

// Key returns the unique key for this reader, and is based on the set of updates on the
// original host environment. This is used to track which initial states have been handled
// already for a profile.
func (r *initialVarReader) Key() initialVarReaderKey {
	// Ensure that this is stable by building an ordered list
	var descs []efi.VariableDescriptor
	for desc := range r.overrides {
		descs = append(descs, desc)
	}
	sort.Slice(descs, func(i, j int) bool {
		return bytes.Compare(descs[i].GUID[:], descs[j].GUID[:]) < 0 || descs[i].Name < descs[j].Name
	})

	// Start with an empty key which corresponds to the original
	// host environment.
	var key initialVarReaderKey

	for _, desc := range descs {
		override := r.overrides[desc]

		h := crypto.SHA1.New()
		h.Write(key[:])
		h.Write(desc.GUID[:])
		binary.Write(h, binary.LittleEndian, uint64(len(desc.Name)))
		binary.Write(h, binary.LittleEndian, uint64(len(override.data)))
		io.WriteString(h, desc.Name)
		h.Write(override.data)

		copy(key[:], h.Sum(nil))
	}

	return key
}

// Copy returns a copy of this initialVarReader.
func (r *initialVarReader) Copy() *initialVarReader {
	out := &initialVarReader{
		varsCtx:   r.varsCtx,
		overrides: make(map[efi.VariableDescriptor]varContents)}
	for k, v := range r.overrides {
		out.overrides[k] = v
	}
	return out
}

// ApplyUpdates applies the specified sequence of updates to this initialVarReader.
func (r *initialVarReader) ApplyUpdates(updates *varUpdate) error {
	// arrange in order of application from oldest to newest
	var updateSlice []*varUpdate
	for ; updates != nil; updates = updates.previous {
		updateSlice = append([]*varUpdate{updates}, updateSlice...)
	}

	for _, update := range updateSlice {
		r.overrides[update.name] = varContents{attrs: update.attrs, data: update.data}
		origData, _, err := efi.ReadVariable(r.varsCtx, update.name.Name, update.name.GUID)
		switch {
		case err == efi.ErrVarNotExist:
			// ok
		case err != nil:
			return err
		case bytes.Equal(update.data, origData):
			// drop this override if it matches the original data
			delete(r.overrides, update.name)
		}
	}

	return nil
}

// variableSetCollector keeps track of all of the starting EFI variable sets that
// a profile needs to be generated against. The profile generation runs an outer
// loop that adds a branch for each of the starting sets. Profile generation may
// add more starting states as some branches have paths that update EFI variables
// (such as applying SBAT updates) which may have an effect on other branches.
type variableSetCollector struct {
	varsCtx context.Context // a context containing the backend for reading EFI variables

	seen map[initialVarReaderKey]struct{} // known starting states

	// todo contains a list of starting sets that a profile branch still
	// needs to be generated for.
	todo []*initialVarReader
}

func newVariableSetCollector(env HostEnvironment) *variableSetCollector {
	varsCtx := env.VarContext()
	return &variableSetCollector{
		varsCtx: varsCtx,
		seen:    map[initialVarReaderKey]struct{}{initialVarReaderKey{}: struct{}{}}, // add the current environment
		todo: []*initialVarReader{
			&initialVarReader{
				varsCtx:   varsCtx,
				overrides: make(map[efi.VariableDescriptor]varContents)}}} // add the current environment
}

// registerUpdateFor is called when a branch updxates an EFI variable. This will
// queue new starting states to process if the updated state hasn't already been
// processed. This should be called on every update - this ensures that if a branch
// makes more than one update, the generated profile will be valid for intermediate
// states.
func (c *variableSetCollector) registerUpdatesFor(initial *initialVarReader, updates *varUpdate) error {
	newInitial := initial.Copy()
	if err := newInitial.ApplyUpdates(updates); err != nil {
		return xerrors.Errorf("cannot compute updated starting state: %w", err)
	}

	key := newInitial.Key()
	if _, exists := c.seen[key]; exists {
		// we've already generated this starting state
		return nil
	}

	c.seen[key] = struct{}{}
	c.todo = append(c.todo, newInitial)

	return nil
}

func (c *variableSetCollector) newVarBranch(root *initialVarReader) *varBranch {
	return &varBranch{
		initial: root,
		registerUpdates: func(updates *varUpdate) error {
			return c.registerUpdatesFor(root, updates)
		}}
}

// More indicates that there are more starting sets to generate profile
// branches for.
func (c *variableSetCollector) More() bool {
	return len(c.todo) > 0
}

// Next returns the next starting set to generate a profile branch for. This will
// not return the same starting set more than once.
func (c *variableSetCollector) Next() *varBranch {
	next := c.todo[0]
	c.todo = c.todo[1:]
	return c.newVarBranch(next)
}

// PeekAll returns all of the pending starting sets to generate profile
// branches for, without consuming them. It allows them to be added to
// with options that run before the profile generation.
func (c *variableSetCollector) PeekAll() []*varBranch {
	var out []*varBranch
	for _, r := range c.todo {
		out = append(out, c.newVarBranch(r))
	}
	return out
}
