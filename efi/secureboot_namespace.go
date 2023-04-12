// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2023 Canonical Ltd
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
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"golang.org/x/xerrors"
)

type (
	newImageLoadHandlerFn func(secureBootAuthoritySet, peImageHandle) (imageLoadHandler, error)
	applyHostVarFixesFn   func(*varBranch) error
)

type secureBootAuthoritySet interface {
	// AddAuthority adds another authority to this namespace which is
	// used when one authority delegates image signing to another authority
	// (eg, via shim's vendor cert) in order to identify images signed by
	// the delegated authority.
	AddAuthority(cert *x509.Certificate)
}

// secureBootAuthorityIdentity corresponds to the identify of a secure boot
// authority. A secure boot namespace has one or more of these.
type secureBootAuthorityIdentity struct {
	subject            []byte
	subjectKeyId       []byte
	publicKeyAlgorithm x509.PublicKeyAlgorithm
}

// withAuthority adds the specified secure boot authority to a secureBootNamespace.
func withAuthority(subject, subjectKeyId []byte, publicKeyAlgorithm x509.PublicKeyAlgorithm) secureBootNamespaceOption {
	return func(ns *secureBootNamespace) {
		ns.authorities = append(ns.authorities, &secureBootAuthorityIdentity{
			subject:            subject,
			subjectKeyId:       subjectKeyId,
			publicKeyAlgorithm: publicKeyAlgorithm})
	}
}

// imagePredicate is used for testing image properties.
type imagePredicate interface {
	Matches(image peImageHandle) (bool, error)
}

type imagePredicateAny []imagePredicate

// imageMatchesAny returns a predicate that is satisfied if any of
// the supplied predicates are satisfied.
func imageMatchesAny(predicates ...imagePredicate) imagePredicate {
	return imagePredicateAny(predicates)
}

func (p imagePredicateAny) Matches(image peImageHandle) (bool, error) {
	for _, pred := range p {
		matches, err := pred.Matches(image)
		if err != nil {
			return false, err
		}
		if matches {
			return true, nil
		}
	}
	return false, nil
}

type imagePredicateAll []imagePredicate

// imageMatchesAll returns a predicate that is satisfied if all of
// the supplied predicates are satisfied.
func imageMatchesAll(predicates ...imagePredicate) imagePredicate {
	return imagePredicateAll(predicates)
}

func (p imagePredicateAll) Matches(image peImageHandle) (bool, error) {
	for _, pred := range p {
		matches, err := pred.Matches(image)
		if err != nil {
			return false, err
		}
		if !matches {
			return false, nil
		}
	}
	return true, nil
}

// errNotHandled is returned from a secureBootNamespaceImageRule if the
// predicate is not satisfied.
var errNotHandled = errors.New("not handled")

// secureBootNamespaceImageRule is a single rule associated with a secure
// boot namespace.
type secureBootNamespaceImageRule struct {
	match  imagePredicate
	create newImageLoadHandlerFn
}

// withImageRule adds the specified rule to a secureBootNamespace.
func withImageRule(match imagePredicate, create newImageLoadHandlerFn) secureBootNamespaceOption {
	return func(ns *secureBootNamespace) {
		ns.rules = append(ns.rules, &secureBootNamespaceImageRule{
			match:  match,
			create: create})
	}
}

// Try determines if the supplied image matches this rule, and returns the
// imageLoadHandler if it does.
func (r *secureBootNamespaceImageRule) Try(ns *secureBootNamespace, image peImageHandle) (imageLoadHandler, error) {
	matches, err := r.match.Matches(image)
	if err != nil {
		return nil, err
	}
	if !matches {
		return nil, errNotHandled
	}
	return r.create(ns, image)
}

type secureBootNamespaceOption func(*secureBootNamespace)

// secureBootNamespace corresponds to a secure boot hierarchy, which is
// associated with one or more authorities and has a set of rules used to
// identify images.
type secureBootNamespace struct {
	name        string
	authorities []*secureBootAuthorityIdentity
	rules       []*secureBootNamespaceImageRule
}

// newSecureBootNamespace constructs a secure boot namespace with the specified
// options.
func newSecureBootNamespace(name string, options ...secureBootNamespaceOption) *secureBootNamespace {
	out := &secureBootNamespace{name: name}
	for _, option := range options {
		option(out)
	}
	return out
}

func (n *secureBootNamespace) String() string {
	return n.name + " secure boot namespace"
}

// AddAuthority implements secureBootAuthoritySet.AddAuthority.
func (n *secureBootNamespace) AddAuthority(cert *x509.Certificate) {
	for _, authority := range n.authorities {
		if bytes.Equal(authority.subject, cert.RawSubject) &&
			bytes.Equal(authority.subjectKeyId, cert.SubjectKeyId) &&
			authority.publicKeyAlgorithm == cert.PublicKeyAlgorithm {
			return
		}
	}

	n.authorities = append(n.authorities, &secureBootAuthorityIdentity{
		subject:            cert.RawSubject,
		subjectKeyId:       cert.SubjectKeyId,
		publicKeyAlgorithm: cert.PublicKeyAlgorithm})
}

func (n *secureBootNamespace) NewImageLoadHandler(image peImageHandle) (imageLoadHandler, error) {
	for _, rule := range n.rules {
		handler, err := rule.Try(n, image)
		switch {
		case err == nil:
			return handler, nil
		case err != errNotHandled:
			return nil, err
		}
	}
	return newNullLoadHandler(n, image)
}

// imageSectionExists is a predicate that is satisfied if an image
// contains a section with the specified name.
type imageSectionExists string

func (p imageSectionExists) Matches(image peImageHandle) (bool, error) {
	return image.HasSection(string(p)), nil
}

// imageSignedByOrganization is a predicate that is satisfied if an
// image is signed by the specified organization.
type imageSignedByOrganization string

func (p imageSignedByOrganization) Matches(image peImageHandle) (bool, error) {
	sigs, err := image.SecureBootSignatures()
	if err != nil {
		return false, err
	}
	for _, sig := range sigs {
		signer := sig.GetSigner()
		if len(signer.Subject.Organization) > 0 && signer.Subject.Organization[0] == string(p) {
			return true, nil
		}
	}
	return false, nil
}

type imageDigestPredicate struct {
	alg    crypto.Hash
	digest []byte
}

func imageDigestMatches(alg crypto.Hash, digest []byte) imagePredicate {
	return &imageDigestPredicate{alg: alg, digest: digest}
}

func (p *imageDigestPredicate) Matches(image peImageHandle) (bool, error) {
	digest, err := image.ImageDigest(p.alg)
	if err != nil {
		return false, err
	}
	return bytes.Equal(digest, p.digest), nil
}

type sbatSectionExistsPredicate struct{}

func (p sbatSectionExistsPredicate) Matches(image peImageHandle) (bool, error) {
	return image.HasSbatSection(), nil
}

// sbatSectionExists is a predicate that is satisfied if an image has
// a .sbat section.
var sbatSectionExists = sbatSectionExistsPredicate{}

// sbatComponentExists is a predicate that is satisfied if an image has
// a SBAT component with the specicied name.
type sbatComponentExists string

func (p sbatComponentExists) Matches(image peImageHandle) (bool, error) {
	components, err := image.SbatComponents()
	if err != nil {
		return false, err
	}
	for _, c := range components {
		if c.Name == string(p) {
			return true, nil
		}
	}
	return false, nil
}

type shimVersionPredicate struct {
	operator string
	version  string
}

func shimVersionIs(operator, version string) imagePredicate {
	return &shimVersionPredicate{
		operator: operator,
		version:  version}
}

func (p *shimVersionPredicate) Matches(image peImageHandle) (bool, error) {
	shim := newShimImageHandle(image)
	x, err := shim.Version()
	if err != nil {
		return false, xerrors.Errorf("cannot obtain shim version: %w", err)
	}

	y := mustParseShimVersion(p.version)

	res := x.Compare(y)
	switch p.operator {
	case ">":
		return res > 0, nil
	case ">=":
		return res >= 0, nil
	case "==":
		return res == 0, nil
	case "!=":
		return res != 0, nil
	case "<=":
		return res <= 0, nil
	case "<":
		return res < 0, nil
	default:
		return false, fmt.Errorf("invalid operator %s", p.operator)
	}
}

type secureBootNamespaceRules interface {
	imageLoadHandlers
}

type secureBootNamespaceRulesImpl struct {
	namespaces []*secureBootNamespace
	fallback   *secureBootNamespace

	handlers map[Image]imageLoadHandler
}

func newSecureBootNamespaceRulesImpl(fallback *secureBootNamespace, namespaces ...*secureBootNamespace) *secureBootNamespaceRulesImpl {
	return &secureBootNamespaceRulesImpl{
		namespaces: namespaces,
		fallback:   fallback,
		handlers:   make(map[Image]imageLoadHandler)}
}

// NewOrExisting implements imageLoadHandlers.
func (r *secureBootNamespaceRulesImpl) NewOrExisting(image peImageHandle) (imageLoadHandler, error) {
	handler, found := r.handlers[image.Source()]
	if found {
		return handler, nil
	}

	// This may return no signatures, but that's ok - in the case, we
	// just return the fallback hierarchy
	sigs, err := image.SecureBootSignatures()
	if err != nil {
		// Reject any image with a badly formed security directory entry
		return nil, xerrors.Errorf("cannot obtain secure boot signatures: %w", err)
	}

	for _, ns := range r.namespaces {
		for _, authority := range ns.authorities {
			cert := &x509.Certificate{
				RawSubject:         authority.subject,
				SubjectKeyId:       authority.subjectKeyId,
				PublicKeyAlgorithm: authority.publicKeyAlgorithm}
			for _, sig := range sigs {
				if sig.CertLikelyTrustAnchor(cert) {
					handler, err := ns.NewImageLoadHandler(image)
					if err != nil {
						return nil, err
					}
					r.handlers[image.Source()] = handler
					return handler, nil
				}
			}
		}
	}

	handler, err = r.fallback.NewImageLoadHandler(image)
	if err != nil {
		return nil, err
	}
	r.handlers[image.Source()] = handler
	return handler, nil
}
