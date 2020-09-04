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
	"bytes"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"

	"golang.org/x/xerrors"
)

// pcrProtectionProfileInstr is a building block of PCRProtectionProfile.
type pcrProtectionProfileInstr interface{}

type pcrProtectionProfileInstrList []pcrProtectionProfileInstr

type pcrProtectionProfileAddPCRValueInstr struct {
	alg   tpm2.HashAlgorithmId
	pcr   int
	value tpm2.Digest
}

type pcrProtectionProfileAddPCRValueFromTPMInstr struct {
	alg tpm2.HashAlgorithmId
	pcr int
}

type pcrProtectionProfileExtendPCRInstr struct {
	alg   tpm2.HashAlgorithmId
	pcr   int
	value tpm2.Digest
}

type pcrProtectionProfileBranchPointInstr struct {
	branches []*PCRProtectionProfile
}

// pcrProtectionProfileEndBranchInstr is a pseudo instruction to mark the end of a branch.
type pcrProtectionProfileEndBranchInstr struct{}

type PCRProtectionProfileBranchPoint struct {
	parent *PCRProtectionProfile
	point  *pcrProtectionProfileBranchPointInstr
}

// PCRProtectionProfile provides a way to define the PCR policy used to protect a key sealed with SealKeyToTPM. It contains a
// sequence of instructions for computing combinations of PCR values that a key will be protected against. The profile is built
// using the methods of this type. A profile can contain branches in order to define PCR policies for multiple conditions, with
// each branch being represented by another PCRProtectionProfile.
type PCRProtectionProfile struct {
	parent *PCRProtectionProfileBranchPoint
	instrs pcrProtectionProfileInstrList
}

func NewPCRProtectionProfile() *PCRProtectionProfile {
	return &PCRProtectionProfile{}
}

// AddPCRValue adds the supplied value to this profile for the specified PCR. This action replaces any value set previously in this
// profile. The function returns the same PCRProtectionProfile so that calls may be chained.
func (p *PCRProtectionProfile) AddPCRValue(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) *PCRProtectionProfile {
	if len(value) != alg.Size() {
		panic("invalid digest length")
	}
	p.instrs = append(p.instrs, &pcrProtectionProfileAddPCRValueInstr{alg: alg, pcr: pcr, value: value})
	return p
}

// AddPCRValueFromTPM adds the current value of the specified PCR to this profile. This action replaces any value set previously in
// this profile. The current value is read back from the TPM when the PCR values generated by this profile are computed. The function
// returns the same PCRProtectionProfile so that calls may be chained.
func (p *PCRProtectionProfile) AddPCRValueFromTPM(alg tpm2.HashAlgorithmId, pcr int) *PCRProtectionProfile {
	p.instrs = append(p.instrs, &pcrProtectionProfileAddPCRValueFromTPMInstr{alg: alg, pcr: pcr})
	return p
}

// ExtendPCR extends the value of the specified PCR in this profile with the supplied value. If this profile doesn't yet have a
// value for the specified PCR, an initial value of all zeroes will be added first. The function returns the same PCRProtectionProfile
// so that calls may be chained.
func (p *PCRProtectionProfile) ExtendPCR(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) *PCRProtectionProfile {
	if len(value) != alg.Size() {
		panic("invalid digest length")
	}
	p.instrs = append(p.instrs, &pcrProtectionProfileExtendPCRInstr{alg: alg, pcr: pcr, value: value})
	return p
}

// AddBranchPoint adds a branch point to the PCR profile from which multiple branches can be added in order to define PCR policies
// for multiple conditions. When a branch point is encountered whilst computing PCR values for a profile, instructions from
// sub-branches are executed before continuing with instructions in the current branch.
func (p *PCRProtectionProfile) AddBranchPoint() *PCRProtectionProfileBranchPoint {
	bp := &pcrProtectionProfileBranchPointInstr{}
	p.instrs = append(p.instrs, bp)
	return &PCRProtectionProfileBranchPoint{parent: p, point: bp}
}

// EndBranch can be called when the caller is finished with this branch, and it returns the branch point in which the branch was
// created. Note that it doesn't make any changes to the current branch and doesn't stop the caller from further modifying the
// branch if it maintains a pointer to it, but it does allow for chaining of function calls.
func (p *PCRProtectionProfile) EndBranch() *PCRProtectionProfileBranchPoint {
	return p.parent
}

// AbortBranch can be called to abort this branch and remove it from the branch point from which it was created. This will result
// in this branch being omitted from the PCR policy computed for the profile. This will panic if called on the root branch. The
// branch point in which this branch was created is returned to allow for the chaining of function calls.
func (p *PCRProtectionProfile) AbortBranch() *PCRProtectionProfileBranchPoint {
	parent := p.parent
	if parent == nil {
		panic("cannot call AbortBranch on a root branch")
	}

	for i, b := range parent.point.branches {
		if b == p {
			if i < len(parent.point.branches)-1 {
				copy(parent.point.branches[i:], parent.point.branches[i+1:])
			}
			parent.point.branches = parent.point.branches[:len(parent.point.branches)-1]
			break
		}
	}
	return parent
}

// NewBranch creates a PCRProtectionProfile corresponding to a new branch, inserts it in to this branch point and returns it.
// Note that each branch created from this branch point must explicitly define values for the same set of PCRs. It is not possible
// to generate policies where each branch defines values for a different set of PCRs.
func (p *PCRProtectionProfileBranchPoint) NewBranch() *PCRProtectionProfile {
	b := &PCRProtectionProfile{parent: p}
	p.point.branches = append(p.point.branches, b)
	return b
}

// EndBranchPoint can be called when the caller is finished adding branches to this branch point, and it returns the branch in which
// the branch point was created. Note that it doesn't make any changes to the current branch point and doesn't stop the caller from
// adding new branches if it maintains a pointer to it, but it does allow for chaining of function calls.
func (p *PCRProtectionProfileBranchPoint) EndBranchPoint() *PCRProtectionProfile {
	return p.parent
}

// pcrProtectionProfileIterator provides a mechanism to perform a depth first traversal of instructions in a PCRProtectionProfile.
type pcrProtectionProfileIterator struct {
	instrs []pcrProtectionProfileInstrList
}

// descendInToProfiles adds instructions from the supplied profiles to the front of the iterator, so that subsequent calls to
// next will return instructions from each of these profiles in turn.
func (iter *pcrProtectionProfileIterator) descendInToBranches(branches ...*PCRProtectionProfile) {
	var instrs []pcrProtectionProfileInstrList
	for _, b := range branches {
		instrs = append(instrs, b.instrs)
	}
	instrs = append(instrs, iter.instrs...)
	iter.instrs = instrs
}

// next returns the next instruction from this iterator. When encountering a branch point, a *pcrProtectionProfileBranchPointInstr
// will be returned, which indicates the number of branches from the branch point. Subsequent calls to next will return instructions
// from each of these branches in turn, with each branch terminating with *pcrProtectionProfileEndBranchInstr. Once all branches have
// been processed, subsequent calls to next will resume returning instructions from the parent branch.
func (iter *pcrProtectionProfileIterator) next() pcrProtectionProfileInstr {
	if len(iter.instrs) == 0 {
		panic("no more instructions")
	}

	for {
		if len(iter.instrs[0]) == 0 {
			iter.instrs = iter.instrs[1:]
			return &pcrProtectionProfileEndBranchInstr{}
		}

		instr := iter.instrs[0][0]
		iter.instrs[0] = iter.instrs[0][1:]

		switch i := instr.(type) {
		case *pcrProtectionProfileBranchPointInstr:
			if len(i.branches) == 0 {
				// If this is an empty branch point, don't return this instruction because there
				// won't be a corresponding *EndBranchInstr
				continue
			}
			iter.descendInToBranches(i.branches...)
			return instr
		default:
			return instr
		}
	}
}

// traverseInstructions returns an iterator that performs a depth first traversal through the instructions in this profile.
func (p *PCRProtectionProfile) traverseInstructions() *pcrProtectionProfileIterator {
	i := &pcrProtectionProfileIterator{}
	i.descendInToBranches(p)
	return i
}

// pcrProtectionProfileStringifyBranchContext is used for maintaining context about branch points during
// PCRProtectionProfile.String()
type pcrProtectionProfileStringifyBranchContext struct {
	index int
	total int
}

func (p *PCRProtectionProfile) String() string {
	var b bytes.Buffer

	contexts := []*pcrProtectionProfileStringifyBranchContext{{index: 0, total: 1}}
	branchStart := false

	iter := p.traverseInstructions()
	for len(contexts) > 0 {
		fmt.Fprintf(&b, "\n")
		depth := len(contexts) - 1
		if branchStart {
			branchStart = false
			fmt.Fprintf(&b, "%*sBranch %d {\n", depth*3, "", contexts[0].index)
		}

		switch i := iter.next().(type) {
		case *pcrProtectionProfileAddPCRValueInstr:
			fmt.Fprintf(&b, "%*s AddPCRValue(%v, %d, %x)", depth*3, "", i.alg, i.pcr, i.value)
		case *pcrProtectionProfileAddPCRValueFromTPMInstr:
			fmt.Fprintf(&b, "%*s AddPCRValueFromTPM(%v, %d)", depth*3, "", i.alg, i.pcr)
		case *pcrProtectionProfileExtendPCRInstr:
			fmt.Fprintf(&b, "%*s ExtendPCR(%v, %d, %x)", depth*3, "", i.alg, i.pcr, i.value)
		case *pcrProtectionProfileBranchPointInstr:
			contexts = append([]*pcrProtectionProfileStringifyBranchContext{{index: 0, total: len(i.branches)}}, contexts...)
			fmt.Fprintf(&b, "%*s BranchPoint(", depth*3, "")
			branchStart = true
		case *pcrProtectionProfileEndBranchInstr:
			contexts[0].index++
			if len(contexts) > 1 {
				// This is the end of a sub-branch rather than the root profile.
				fmt.Fprintf(&b, "%*s}", depth*3, "")
			}
			switch {
			case contexts[0].index < contexts[0].total:
				// There are sibling branches to print.
				branchStart = true
			case len(contexts) > 1:
				// This is the end of a branch point. Printing will continue with the parent branch.
				fmt.Fprintf(&b, "\n%*s )", (depth-1)*3, "")
				fallthrough
			default:
				// Return to the parent branch's context.
				contexts = contexts[1:]
			}
		}
	}

	return b.String()
}

// pcrProtectionProfileCanonicalizeContext is used for maintaining context during PCRProtectionProfile.canonicalize(). It is
// associated with a single branch and consists of all of the alternative instruction sequences until the current point of execution,
// and contains a reference to its parent context.
type pcrProtectionProfileCanonicalizeContext struct {
	parent *pcrProtectionProfileCanonicalizeContext
	instrs []pcrProtectionProfileInstrList
}

func (c *pcrProtectionProfileCanonicalizeContext) isRoot() bool {
	return c.parent == nil
}

// pcrProtectionProfileCanonicalizeContextStack is a slice of contexts used to maintain context across branch points during
// PCRProtectionProfile.canonicalize().
type pcrProtectionProfileCanonicalizeContextStack []*pcrProtectionProfileCanonicalizeContext

func (s pcrProtectionProfileCanonicalizeContextStack) handleBranchPoint(n int) (out pcrProtectionProfileCanonicalizeContextStack) {
	for i := 0; i < n; i++ {
		c := &pcrProtectionProfileCanonicalizeContext{parent: s.top()}
		for _, l := range s.top().instrs {
			l2 := make(pcrProtectionProfileInstrList, len(l))
			copy(l2, l)
			c.instrs = append(c.instrs, l2)
		}
		out = append(out, c)
	}
	s.top().instrs = nil
	out = append(out, s...)
	return
}

func (s pcrProtectionProfileCanonicalizeContextStack) handleEndBranch() pcrProtectionProfileCanonicalizeContextStack {
	for _, l := range s.top().instrs {
		s.top().parent.instrs = append(s.top().parent.instrs, l)
	}
	return s[1:]
}

func (s pcrProtectionProfileCanonicalizeContextStack) top() *pcrProtectionProfileCanonicalizeContext {
	return s[0]
}

// canonicalize converts an arbitrarily complex profile in to a profile starting with a single branch point and then
// branches of instructions with no other branch points.
func (p *PCRProtectionProfile) canonicalize() *PCRProtectionProfile {
	contexts := pcrProtectionProfileCanonicalizeContextStack{{instrs: make([]pcrProtectionProfileInstrList, 1)}}

	iter := p.traverseInstructions()
	for {
		instr := iter.next()
		switch i := instr.(type) {
		case *pcrProtectionProfileBranchPointInstr:
			contexts = contexts.handleBranchPoint(len(i.branches))
		case *pcrProtectionProfileEndBranchInstr:
			if contexts.top().isRoot() {
				var branches []*PCRProtectionProfile
				for _, l := range contexts.top().instrs {
					branches = append(branches, &PCRProtectionProfile{instrs: l})
				}
				return &PCRProtectionProfile{instrs: pcrProtectionProfileInstrList{&pcrProtectionProfileBranchPointInstr{branches: branches}}}
			}
			contexts = contexts.handleEndBranch()
		default:
			for i := range contexts.top().instrs {
				contexts.top().instrs[i] = append(contexts.top().instrs[i], instr)
			}
		}
	}
}

// computePCRValues computes a list of different PCR value combinations from this PCRProtectionProfile.
func (p *PCRProtectionProfile) computePCRValues(tpm *tpm2.TPMContext) ([]tpm2.PCRValues, error) {
	var values []tpm2.PCRValues
	var total int
	v := make(tpm2.PCRValues)

	iter := p.canonicalize().traverseInstructions()
	for {
		switch i := iter.next().(type) {
		case *pcrProtectionProfileAddPCRValueInstr:
			v.SetValue(i.alg, i.pcr, i.value)
		case *pcrProtectionProfileAddPCRValueFromTPMInstr:
			if tpm == nil {
				return nil, fmt.Errorf("cannot read current value of PCR %d from bank %v: no TPM context", i.pcr, i.alg)
			}
			_, tv, err := tpm.PCRRead(tpm2.PCRSelectionList{{Hash: i.alg, Select: []int{i.pcr}}})
			if err != nil {
				return nil, xerrors.Errorf("cannot read current value of PCR %d from bank %v: %w", i.pcr, i.alg, err)
			}
			v.SetValue(i.alg, i.pcr, tv[i.alg][i.pcr])
		case *pcrProtectionProfileExtendPCRInstr:
			if _, ok := v[i.alg]; !ok {
				v[i.alg] = make(map[int]tpm2.Digest)
			}
			if _, ok := v[i.alg][i.pcr]; !ok {
				v[i.alg][i.pcr] = make(tpm2.Digest, i.alg.Size())
			}
			h := i.alg.NewHash()
			h.Write(v[i.alg][i.pcr])
			h.Write(i.value)
			v[i.alg][i.pcr] = h.Sum(nil)
		case *pcrProtectionProfileBranchPointInstr:
			if total > 0 {
				panic("unexpected branch point in canonicalized profile")
			}
			total = len(i.branches)
		case *pcrProtectionProfileEndBranchInstr:
			values = append(values, v)
			if len(values) == total {
				return values, nil
			}
			v = make(tpm2.PCRValues)
		}
	}
}

// computePCRDigests computes a PCR selection and list of PCR digests from this PCRProtectionProfile. The returned list of PCR digests
// is de-duplicated.
func (p *PCRProtectionProfile) computePCRDigests(tpm *tpm2.TPMContext, alg tpm2.HashAlgorithmId) (tpm2.PCRSelectionList, tpm2.DigestList, error) {
	// Compute the sets of PCR values for all branches
	values, err := p.computePCRValues(tpm)
	if err != nil {
		return nil, nil, err
	}

	// Compute the PCR selection for this profile from the first branch.
	pcrs := values[0].SelectionList()

	// Compute the PCR digests for all branches, making sure that they all contain values for the same sets of PCRs.
	var pcrDigests tpm2.DigestList
	for _, v := range values {
		p, digest, _ := tpm2.ComputePCRDigestSimple(alg, v)
		if !p.Equal(pcrs) {
			return nil, nil, errors.New("not all branches contain values for the same sets of PCRs")
		}
		pcrDigests = append(pcrDigests, digest)
	}

	var uniquePcrDigests tpm2.DigestList
	for _, d := range pcrDigests {
		found := false
		for _, f := range uniquePcrDigests {
			if bytes.Equal(d, f) {
				found = true
				break
			}
		}
		if found {
			continue
		}
		uniquePcrDigests = append(uniquePcrDigests, d)
	}

	return pcrs, uniquePcrDigests, nil
}
