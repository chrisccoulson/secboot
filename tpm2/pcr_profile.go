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

package tpm2

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/util"

	"golang.org/x/xerrors"
)

// pcrValuesList is a list of PCR value combinations computed from PCRProtectionProfile.
type pcrValuesList []tpm2.PCRValues

// setValue sets the specified PCR to the supplied value for all branches.
func (l pcrValuesList) setValue(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) {
	for _, v := range l {
		v.SetValue(alg, pcr, value)
	}
}

// extendValue extends the specified PCR with the supplied value for all branches.
func (l pcrValuesList) extendValue(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) {
	for _, v := range l {
		if _, ok := v[alg]; !ok {
			v[alg] = make(map[int]tpm2.Digest)
		}
		if _, ok := v[alg][pcr]; !ok {
			v[alg][pcr] = make(tpm2.Digest, alg.Size())
		}
		h := alg.NewHash()
		h.Write(v[alg][pcr])
		h.Write(value)
		v[alg][pcr] = h.Sum(nil)
	}
}

func (l pcrValuesList) copy() (out pcrValuesList) {
	for _, v := range l {
		ov := make(tpm2.PCRValues)
		for alg := range v {
			ov[alg] = make(map[int]tpm2.Digest)
			for pcr := range v[alg] {
				ov[alg][pcr] = v[alg][pcr]
			}
		}
		out = append(out, ov)
	}
	return
}

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

type pcrProtectionProfileResumeBranchInstr struct{}

type pcrProtectionProfileBeginBranchInstr struct{}

type PCRProtectionProfileBranchPoint struct {
	parent *PCRProtectionProfile
	point  *pcrProtectionProfileBranchPointInstr
}

// PCRProtectionProfile provides a way to define the PCR policy used to
// protect a key sealed with SealKeyToTPM. It contains a sequence of
// instructions for computing combinations of PCR values that a key will be
// protected against. The profile is built using the methods of this type.
// A profile can contain branches in order to define PCR policies for multiple
// conditions, with each branch being represented by another PCRProtectionProfile.
//
// Sequences of instructions within a branch form a logical AND. Branches from
// each branch point form a logical OR.
type PCRProtectionProfile struct {
	parent *PCRProtectionProfileBranchPoint
	instrs pcrProtectionProfileInstrList
}

// NewPCRProtectionProfile creates an empty profile.
func NewPCRProtectionProfile() *PCRProtectionProfile {
	return &PCRProtectionProfile{}
}

// AddPCRValue adds the supplied value to this branch for the specified PCR.
// This action replaces any value set previously for this PCR in this branch.
// The function returns the same PCRProtectionProfile so that calls may be
// chained.
func (p *PCRProtectionProfile) AddPCRValue(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) *PCRProtectionProfile {
	if len(value) != alg.Size() {
		panic("invalid digest length")
	}
	p.instrs = append(p.instrs, &pcrProtectionProfileAddPCRValueInstr{alg: alg, pcr: pcr, value: value})
	return p
}

// AddPCRValueFromTPM adds the current value of the specified PCR to this
// branch. This action replaces any value set previously for this PCR in
// this branch. The current value is read back from the TPM when the PCR
// values generated by this profile are computed. The function returns the
// same PCRProtectionProfile so that calls may be chained.
func (p *PCRProtectionProfile) AddPCRValueFromTPM(alg tpm2.HashAlgorithmId, pcr int) *PCRProtectionProfile {
	p.instrs = append(p.instrs, &pcrProtectionProfileAddPCRValueFromTPMInstr{alg: alg, pcr: pcr})
	return p
}

// ExtendPCR extends the value of the specified PCR in this branch with the
// supplied value. If this branch doesn't yet have a value for the specified
// PCR, an initial value of all zeroes will be added first. The function
// returns the same PCRProtectionProfile so that calls may be chained.
func (p *PCRProtectionProfile) ExtendPCR(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) *PCRProtectionProfile {
	if len(value) != alg.Size() {
		panic("invalid digest length")
	}
	p.instrs = append(p.instrs, &pcrProtectionProfileExtendPCRInstr{alg: alg, pcr: pcr, value: value})
	return p
}

// AddBranchPoint adds a branch point to this branch from which multiple
// sub-branches can be added in order to define PCR policies for multiple
// conditions. When a branch point is encountered whilst computing PCR values
// for a profile, instructions from sub-branches are executed before continuing
// with instructions in the current branch.
//
// Instructions added to this branch after this point will apply to all of the
// sub-branches created at this branch point.
func (p *PCRProtectionProfile) AddBranchPoint() *PCRProtectionProfileBranchPoint {
	bp := &pcrProtectionProfileBranchPointInstr{}
	p.instrs = append(p.instrs, bp)
	return &PCRProtectionProfileBranchPoint{parent: p, point: bp}
}

// EndBranch can be called when the caller is finished with this branch, and it
// returns the branch point in which the branch was created. Note that it doesn't
// make any changes to the current branch and doesn't stop the caller from further
// modifying the branch if it maintains a pointer to it, but it does allow for
// chaining of function calls.
func (p *PCRProtectionProfile) EndBranch() *PCRProtectionProfileBranchPoint {
	return p.parent
}

// AddBranches adds a branch point to this branch containing the supplied
// sub-profiles as branches, in order to define PCR policies for multiple conditions.
// When a branch point is encountered whilst computing PCR values for a profile,
// instructions from sub-branches are executed before continuing with instructions
// in the current branch. Each sub-branch inherits context created by the parent
// branch.
//
// Instructions added to this branch after this point will apply to all of the
// sub-branches added at this point.
//
// Note that each sub-branch added here must explicitly define values for the same
// set of PCRs. It is not possible to generate policies where each branch defines
// values for a different set of PCRs.
func (p *PCRProtectionProfile) AddBranches(branches ...*PCRProtectionProfile) *PCRProtectionProfile {
	p.instrs = append(p.instrs, &pcrProtectionProfileBranchPointInstr{branches: branches})
	return p
}

// AbortBranch can be called to abort this branch and remove it from the branch
// point from which it was created. This will result in this branch being omitted
// from the PCR policy computed for the profile. This will panic if called on the
// root branch. The branch point in which this branch was created is returned to
// allow for the chaining of function calls.
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

// NewBranch creates a PCRProtectionProfile corresponding to a new branch, inserts
// it in to this branch point and returns it. When computing PCR values for this
// profile, the new branch inherits context created by the parent branch.
//
// Note that each branch created from this branch point must explicitly define
// values for the same set of PCRs. It is not possible to generate policies where
// each branch defines values for a different set of PCRs.
func (p *PCRProtectionProfileBranchPoint) NewBranch() *PCRProtectionProfile {
	b := &PCRProtectionProfile{parent: p}
	p.point.branches = append(p.point.branches, b)
	return b
}

// EndBranchPoint can be called when the caller is finished adding branches to
// this branch point, and it returns the branch in which the branch point was
// created in order to continue adding instructions. Note that it doesn't make
// any changes to the current branch point and doesn't stop the caller from
// adding new branches if it maintains a pointer to it, but it does allow for
// chaining of function calls.
func (p *PCRProtectionProfileBranchPoint) EndBranchPoint() *PCRProtectionProfile {
	return p.parent
}

// pcrProfileBranchVisitor is an interface to receive instructions associated
// with a branch.
type pcrProfileBranchVisitor interface {
	// beginBranch is called before the first instruction in this branch.
	beginBranch()

	// addPCRValue is called to add the supplied PCR value to this branch.
	addPCRValue(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest)

	// addPCRValueFromTPM is called to add the value of the specified
	// PCR to this branch,
	addPCRValueFromTPM(alg tpm2.HashAlgorithmId, pcr int) error

	// extendPCR is called to extend the specified PCR with the supplied
	// value for this branch.
	extendPCR(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest)

	// branchPoint signals that this branch branches into n number of
	// sub-branches at this point. The implementation returns visitors
	// for each of the sub-branches. Traversal will continue into each
	// of the sub-branches before continuing with the current branch.
	branchPoint(n int) []pcrProfileBranchVisitor

	// resumeBranch signals that the processing of sub-branches for
	// the current branch point has completed.
	resumeBranch()

	// endBranch signals the end of this branch.
	endBranch()
}

type pcrProfileTraverseBranchContext struct {
	instrs  pcrProtectionProfileInstrList
	visitor pcrProfileBranchVisitor
}

// pcrProfileTraverseContext is used for the traversal of a PCRProtectionProfile.
type pcrProfileTraverseContext struct {
	branches []*pcrProfileTraverseBranchContext
}

func (c *pcrProfileTraverseContext) run() error {
	for len(c.branches) > 0 {
		// Pick the current branch
		currentBranch := c.branches[0]
		visitor := currentBranch.visitor

		if len(currentBranch.instrs) == 0 {
			// This branch is finished - move to the next one
			visitor.endBranch()
			c.branches = c.branches[1:]
			continue
		}

		// Pick the next instruction for this branch
		instr := currentBranch.instrs[0]
		currentBranch.instrs = currentBranch.instrs[1:]

		switch i := instr.(type) {
		case *pcrProtectionProfileBeginBranchInstr:
			visitor.beginBranch()
		case *pcrProtectionProfileAddPCRValueInstr:
			visitor.addPCRValue(i.alg, i.pcr, i.value)
		case *pcrProtectionProfileAddPCRValueFromTPMInstr:
			if err := visitor.addPCRValueFromTPM(i.alg, i.pcr); err != nil {
				return err
			}
		case *pcrProtectionProfileExtendPCRInstr:
			visitor.extendPCR(i.alg, i.pcr, i.value)
		case *pcrProtectionProfileBranchPointInstr:
			visitors := visitor.branchPoint(len(i.branches))

			// Prepend a resumeBranch instruction to the current branch that
			// will be executed once we have finished processing sub-branches
			currentBranch.instrs = append(pcrProtectionProfileInstrList{&pcrProtectionProfileResumeBranchInstr{}},
				currentBranch.instrs...)

			var newBranches []*pcrProfileTraverseBranchContext
			for j := range i.branches {
				newBranches = append(newBranches,
					&pcrProfileTraverseBranchContext{
						instrs: append(pcrProtectionProfileInstrList{&pcrProtectionProfileBeginBranchInstr{}},
							i.branches[j].instrs...),
						visitor: visitors[j]})
			}
			// Prepend the sub-branches to the list of branches to process - the
			// first sub-branch becomes the current branch
			c.branches = append(newBranches, c.branches...)
		case *pcrProtectionProfileResumeBranchInstr:
			// We've finsished processing all sub-branches for a branch
			// point and are resuming the parent branch
			visitor.resumeBranch()
		}
	}

	return nil
}

func (p *PCRProtectionProfile) traverseInstructions(visitor pcrProfileBranchVisitor) error {
	c := &pcrProfileTraverseContext{
		branches: []*pcrProfileTraverseBranchContext{
			&pcrProfileTraverseBranchContext{
				instrs: append(pcrProtectionProfileInstrList{&pcrProtectionProfileBeginBranchInstr{}},
					p.instrs...),
				visitor: visitor}}}
	return c.run()
}

type pcrProfileBranchStringVisitor struct {
	w     io.Writer
	depth int
	index int
}

func (v *pcrProfileBranchStringVisitor) beginBranch() {
	if v.depth == 0 {
		return
	}
	fmt.Fprintf(v.w, "\n%*sBranch %d {", v.depth*3, "", v.index)
}

func (v *pcrProfileBranchStringVisitor) addPCRValue(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) {
	fmt.Fprintf(v.w, "\n%*s AddPCRValue(%v, %d, %x)", v.depth*3, "", alg, pcr, value)
}

func (v *pcrProfileBranchStringVisitor) addPCRValueFromTPM(alg tpm2.HashAlgorithmId, pcr int) error {
	fmt.Fprintf(v.w, "\n%*s AddPCRValueFromTPM(%v, %d)", v.depth*3, "", alg, pcr)
	return nil
}

func (v *pcrProfileBranchStringVisitor) extendPCR(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) {
	fmt.Fprintf(v.w, "\n%*s ExtendPCR(%v, %d, %x)", v.depth*3, "", alg, pcr, value)
}

func (v *pcrProfileBranchStringVisitor) branchPoint(n int) (out []pcrProfileBranchVisitor) {
	fmt.Fprintf(v.w, "\n%*s BranchPoint(", v.depth*3, "")
	for i := 0; i < n; i++ {
		out = append(out, &pcrProfileBranchStringVisitor{w: v.w, depth: v.depth + 1, index: i})
	}
	return out
}

func (v *pcrProfileBranchStringVisitor) resumeBranch() {
	fmt.Fprintf(v.w, "\n%*s )", v.depth*3, "")
}

func (v *pcrProfileBranchStringVisitor) endBranch() {
	if v.depth == 0 {
		return
	}
	fmt.Fprintf(v.w, "\n%*s}", v.depth*3, "")
}

func (p *PCRProtectionProfile) String() string {
	s := new(bytes.Buffer)
	p.traverseInstructions(&pcrProfileBranchStringVisitor{w: s})
	return s.String() + "\n"
}

type pcrProfileBranchComputeVisitor struct {
	tpm                *tpm2.TPMContext
	values             pcrValuesList
	currentBranchPoint []*pcrProfileBranchComputeVisitor
}

func (v *pcrProfileBranchComputeVisitor) beginBranch() {}

func (v *pcrProfileBranchComputeVisitor) addPCRValue(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) {
	v.values.setValue(alg, pcr, value)
}

func (v *pcrProfileBranchComputeVisitor) addPCRValueFromTPM(alg tpm2.HashAlgorithmId, pcr int) error {
	if v.tpm == nil {
		return fmt.Errorf("cannot read current value of PCR %d from bank %v: no TPM context", pcr, alg)
	}
	_, values, err := v.tpm.PCRRead(tpm2.PCRSelectionList{{Hash: alg, Select: []int{pcr}}})
	if err != nil {
		return xerrors.Errorf("cannot read current value of PCR %d from bank %v: %w", pcr, alg, err)
	}
	v.values.setValue(alg, pcr, values[alg][pcr])
	return nil
}

func (v *pcrProfileBranchComputeVisitor) extendPCR(alg tpm2.HashAlgorithmId, pcr int, value tpm2.Digest) {
	v.values.extendValue(alg, pcr, value)
}

func (v *pcrProfileBranchComputeVisitor) branchPoint(n int) (out []pcrProfileBranchVisitor) {
	// When we encounter a branch point, we take a snapshot of the current context and
	// copy it to each sub-branch for it to be modified.
	for i := 0; i < n; i++ {
		branch := &pcrProfileBranchComputeVisitor{tpm: v.tpm, values: v.values.copy()}
		v.currentBranchPoint = append(v.currentBranchPoint, branch)
		out = append(out, branch)
	}
	return out
}

func (v *pcrProfileBranchComputeVisitor) resumeBranch() {
	// When we resume a branch after executing sub-branches, we clear our own context
	// and then set it to the concatenation of the context associated with every
	// sub-branch, which originally inherited our own context.
	if len(v.currentBranchPoint) == 0 {
		// This was an empty branch point.
		return
	}

	v.values = nil
	for _, branch := range v.currentBranchPoint {
		v.values = append(v.values, branch.values...)
	}

	v.currentBranchPoint = nil
}

func (v *pcrProfileBranchComputeVisitor) endBranch() {}

// ComputePCRValues computes PCR values for this PCRProtectionProfile, returning one
// set of PCR values for each complete branch. The returned list of PCR values is not
// de-duplicated.
func (p *PCRProtectionProfile) ComputePCRValues(tpm *tpm2.TPMContext) ([]tpm2.PCRValues, error) {
	visitor := &pcrProfileBranchComputeVisitor{tpm: tpm, values: pcrValuesList{make(tpm2.PCRValues)}}
	if err := p.traverseInstructions(visitor); err != nil {
		return nil, err
	}

	return []tpm2.PCRValues(visitor.values), nil
}

// ComputePCRDigests computes a PCR selection and a list of composite PCR digests
// from this PCRProtectionProfile (one composite digest per complete branch). The
// returned list of PCR digests is de-duplicated.
func (p *PCRProtectionProfile) ComputePCRDigests(tpm *tpm2.TPMContext, alg tpm2.HashAlgorithmId) (tpm2.PCRSelectionList, tpm2.DigestList, error) {
	// Compute the sets of PCR values for all branches
	values, err := p.ComputePCRValues(tpm)
	if err != nil {
		return nil, nil, err
	}

	// Compute the PCR selection for this profile from the first branch.
	pcrs := values[0].SelectionList()

	// Compute the PCR digests for all branches, making sure that they all contain values for the same sets of PCRs.
	var pcrDigests tpm2.DigestList
	for _, v := range values {
		p, digest, err := util.ComputePCRDigestFromAllValues(alg, v)
		if err != nil {
			return nil, nil, xerrors.Errorf("cannot compute PCR digest: %w", err)
		}
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
