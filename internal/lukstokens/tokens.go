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

package lukstokens

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot/internal/luks2"
)

const (
	KeyDataTokenType  luks2.TokenType = "ubuntu-fde"
	RecoveryTokenType luks2.TokenType = "ubuntu-fde-recovery"
)

func init() {
	luks2.RegisterTokenDecoder(KeyDataTokenType, func(data []byte) (luks2.Token, error) {
		var token *KeyDataToken
		if err := json.Unmarshal(data, &token); err != nil {
			return nil, err
		}
		return token, nil
	})

	luks2.RegisterTokenDecoder(RecoveryTokenType, func(data []byte) (luks2.Token, error) {
		var token *RecoveryToken
		if err := json.Unmarshal(data, &token); err != nil {
			return nil, err
		}
		return token, nil
	})
}

// NamedToken corresponds to a token created by secboot, which identifies
// the associated keyslot with a name and may contain data required to
// activate a volume using the associated keyslot.
type NamedToken interface {
	luks2.Token

	// Name returns the name of this token. A name is an arbitrary
	// string used to identify the associated keyslot, and the name is
	// intended to be unique between keyslots.
	Name() string
}

type tokenKeyslots []int

func (k tokenKeyslots) MarshalJSON() ([]byte, error) {
	var keyslots []luks2.JsonNumber
	for _, slot := range k {
		keyslots = append(keyslots, luks2.JsonNumber(strconv.Itoa(slot)))
	}
	return json.Marshal(keyslots)
}

func (k *tokenKeyslots) UnmarshalJSON(data []byte) error {
	var rawslots []luks2.JsonNumber
	if err := json.Unmarshal(data, &rawslots); err != nil {
		return err
	}

	var keyslots tokenKeyslots
	for _, v := range rawslots {
		slot, err := v.Int()
		if err != nil {
			return xerrors.Errorf("invalid keyslot ID: %w", err)
		}
		keyslots = append(keyslots, slot)
	}
	*k = keyslots
	return nil
}

type tokenBaseRaw struct {
	Type     luks2.TokenType `json:"type"`
	Keyslots tokenKeyslots   `json:"keyslots"`
	Name     string          `json:"ubuntu_fde_name"`
}

type recoveryTokenRaw struct {
	tokenBaseRaw
}

type keyDataTokenRaw struct {
	tokenBaseRaw
	Priority int             `json:"ubuntu_fde_priority"`
	Data     json.RawMessage `json:"ubuntu_fde_data,omitempty"`
}

// TokenBase provides the fields that are common to all tokens created by secboot.
type TokenBase struct {
	// TokenKeyslots is the keyslots associated with this token, by ID.
	// We associate each token with only one keyslot, so this should
	// always have a length of one.
	TokenKeyslots []int

	TokenName string // The name of the keyslot that this token is associated with
}

func (t *TokenBase) Keyslots() []int {
	return t.TokenKeyslots
}

func (t *TokenBase) Name() string {
	return t.TokenName
}

// RecoveryToken represents a token with the type "ubuntu-fde-recovery",
// associated with a recovery keyslot
type RecoveryToken struct {
	TokenBase
}

func (t *RecoveryToken) Type() luks2.TokenType {
	return RecoveryTokenType
}

func (t *RecoveryToken) MarshalJSON() ([]byte, error) {
	raw := &recoveryTokenRaw{
		tokenBaseRaw: tokenBaseRaw{
			Type:     RecoveryTokenType,
			Keyslots: tokenKeyslots(t.TokenKeyslots),
			Name:     t.TokenName}}
	return json.Marshal(raw)
}

func (t *RecoveryToken) UnmarshalJSON(data []byte) error {
	var raw *recoveryTokenRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	*t = RecoveryToken{
		TokenBase: TokenBase{
			TokenKeyslots: []int(raw.Keyslots),
			TokenName:     raw.Name}}
	return nil
}

// KeyDataToken represents a token with the "ubuntu-fde" type, associated
// with a platform protected keyslot. It is created as a placeholder when
// a keyslot is created, and then is subsequently updated to contain an
// encoded KeyData.
type KeyDataToken struct {
	TokenBase

	// Priority is the priority of the keyslot associated with
	// this token. 1 is the default, with higher numbers indicating a
	// higher priority. 0 means that the associated keyslot shouldn't be
	// used unless requested explicitly by name.
	Priority int

	Data json.RawMessage // The raw KeyData JSON payload
}

func (t *KeyDataToken) Type() luks2.TokenType {
	return KeyDataTokenType
}

func (t *KeyDataToken) MarshalJSON() ([]byte, error) {
	raw := &keyDataTokenRaw{
		tokenBaseRaw: tokenBaseRaw{
			Type:     KeyDataTokenType,
			Keyslots: tokenKeyslots(t.TokenKeyslots),
			Name:     t.TokenName},
		Priority: t.Priority,
		Data:     t.Data}
	return json.Marshal(raw)
}

func (t *KeyDataToken) UnmarshalJSON(data []byte) error {
	var raw *keyDataTokenRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	*t = KeyDataToken{
		TokenBase: TokenBase{
			TokenKeyslots: []int(raw.Keyslots),
			TokenName:     raw.Name},
		Priority: raw.Priority,
		Data:     raw.Data}
	return nil
}

// isValidNamedToken determines if the token is valid by checking it
// has a name and that it is associated with one keyslot.
func isValidNamedToken(token NamedToken) bool {
	return token.Name() != "" && len(token.Keyslots()) == 1
}

type namedTokenData struct {
	id    int
	token NamedToken
}

// TokenView provides a read-only representation of all of the named tokens
// associated with a LUKS2 header.
type TokenView struct {
	// allTokens contains every token in a LUKS header, including those
	// that aren't valid named tokens managed by this package.
	allTokens map[int]luks2.Token

	// namedTokens contains a map of keyslot name to valid named tokens.
	namedTokens map[string]namedTokenData
}

func NewTokenView(header *luks2.HeaderInfo) (*TokenView, error) {
	view := &TokenView{
		allTokens:   header.Metadata.Tokens,
		namedTokens: make(map[string]namedTokenData)}

	for id, token := range header.Metadata.Tokens {
		named, ok := token.(NamedToken)
		if !ok {
			continue
		}

		if !isValidNamedToken(named) {
			continue
		}

		if _, exists := view.namedTokens[named.Name()]; exists {
			return nil, fmt.Errorf("multiple tokens with the same name (%s)", named.Name())
		}

		view.namedTokens[named.Name()] = namedTokenData{id: id, token: named}
	}

	return view, nil
}

// ListNames returns a sorted list of all of the keyslot names from this view.
func (v *TokenView) ListNames() (names []string) {
	for name := range v.namedTokens {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// TokenByName returns the token and its ID for the keyslot with the supplied name.
func (v *TokenView) TokenByName(name string) (token NamedToken, id int, exists bool) {
	data, exists := v.namedTokens[name]
	if !exists {
		return nil, 0, false
	}
	return data.token, data.id, true
}

// NameInUse indicates whenther the supplied name is already in use.
func (v *TokenView) NameInUse(name string) (exists bool) {
	_, exists = v.namedTokens[name]
	return exists
}

// KeyDataTokensByPriority returns all of the key data tokens in order of priority,
// from highest to lowest. Tokens with the same priority are returned in the order in
// which their names are sorted. This omits any with a priority of 0.
func (v *TokenView) KeyDataTokensByPriority() (tokens []*KeyDataToken) {
	// Build a map of tokens by priority
	tokensByPriority := make(map[int][]*KeyDataToken)
	for _, name := range v.ListNames() {
		t := v.namedTokens[name].token

		if t.Type() != KeyDataTokenType {
			continue
		}

		token := t.(*KeyDataToken)

		if token.Priority < 1 {
			// Priority 0 tokens are ignored unless called explicitly
			// by name.
			continue
		}
		tokensByPriority[token.Priority] = append(tokensByPriority[token.Priority], token)
	}

	// Create a list of priorites, sorted in reverse order (highest to lowest)
	priorities := make([]int, 0, len(tokensByPriority))
	for priority := range tokensByPriority {
		priorities = append(priorities, priority)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(priorities)))

	// Build the list of tokens in priority order (highest to lowest)
	for _, priority := range priorities {
		tokens = append(tokens, tokensByPriority[priority]...)
	}

	return tokens
}

// OrphanedTokenIds returns a list of ids for tokens that have been orphaned
// and can be removed. Orphaned tokens are those where the associated keyslot
// doesn't has been deleted and can occur if the process of removing a keyslot
// and its tokens is interrupted.
func (v *TokenView) OrphanedTokenIds() (out []int) {
	for id, token := range v.allTokens {
		if len(token.Keyslots()) != 0 {
			continue
		}

		if _, ok := token.(NamedToken); !ok {
			continue
		}

		// Cryptsetup removes the keyslot ID from associated tokens
		// when the slot is deleted, so a token with no associated
		// keyslots is orphaned.
		out = append(out, id)
	}

	sort.Ints(out)
	return out
}
