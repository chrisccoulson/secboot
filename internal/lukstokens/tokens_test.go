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

package lukstokens_test

import (
	"encoding/json"
	"strconv"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot/internal/luks2"
	"github.com/snapcore/secboot/internal/luks2/luks2test"
	"github.com/snapcore/secboot/internal/testutil"
	. "github.com/snapcore/secboot/internal/token"
)

func Test(t *testing.T) { TestingT(t) }

type tokenSuite struct{}

var _ = Suite(&tokenSuite{})

func (s *tokenSuite) checkTokenBaseJSON(c *C, j map[string]interface{}, token *TokenBase, typ luks2.TokenType) {
	t, ok := j["type"].(string)
	c.Check(ok, testutil.IsTrue)
	c.Check(t, Equals, string(typ))

	keyslots, ok := j["keyslots"].([]interface{})
	c.Check(ok, testutil.IsTrue)
	for i, v := range keyslots {
		slot, ok := v.(string)
		c.Check(ok, testutil.IsTrue)
		c.Check(slot, Equals, strconv.Itoa(token.Keyslots()[i]))
	}

	name, ok := j["ubuntu_fde_name"].(string)
	c.Check(ok, testutil.IsTrue)
	c.Check(name, Equals, token.Name())
}

func (s *tokenSuite) checkRecoveryTokenJSON(c *C, data []byte, token *RecoveryToken) {
	var j map[string]interface{}
	c.Assert(json.Unmarshal(data, &j), IsNil)

	s.checkTokenBaseJSON(c, j, &token.TokenBase, RecoveryTokenType)
}

func (s *tokenSuite) TestMarshalRecoveryToken1(c *C) {
	token := &RecoveryToken{
		TokenBase: TokenBase{
			TokenName:     "foo-recovery",
			TokenKeyslots: []int{1}}}
	data, err := json.Marshal(token)
	c.Check(err, IsNil)

	s.checkRecoveryTokenJSON(c, data, token)
}

func (s *tokenSuite) TestMarshalRecoveryToken2(c *C) {
	token := &RecoveryToken{
		TokenBase: TokenBase{
			TokenName:     "recovery-bar",
			TokenKeyslots: []int{7}}}
	data, err := json.Marshal(token)
	c.Check(err, IsNil)

	s.checkRecoveryTokenJSON(c, data, token)
}

func (s *tokenSuite) TestUnmarshalRecoveryToken1(c *C) {
	token := &RecoveryToken{
		TokenBase: TokenBase{
			TokenName:     "foo-recovery",
			TokenKeyslots: []int{1}}}
	data, err := json.Marshal(token)
	c.Check(err, IsNil)

	var token2 *RecoveryToken
	c.Check(json.Unmarshal(data, &token2), IsNil)
	c.Check(token2, DeepEquals, token)
}

func (s *tokenSuite) TestUnmarshalRecoveryToken2(c *C) {
	token := &RecoveryToken{
		TokenBase: TokenBase{
			TokenName:     "recovery-bar",
			TokenKeyslots: []int{7}}}
	data, err := json.Marshal(token)
	c.Check(err, IsNil)

	var token2 *RecoveryToken
	c.Check(json.Unmarshal(data, &token2), IsNil)
	c.Check(token2, DeepEquals, token)
}

func (s *tokenSuite) TestDecodeRecoveryToken(c *C) {
	if luks2.DetectCryptsetupFeatures()&luks2.FeatureTokenImport == 0 {
		c.Skip("cryptsetup doesn't support token import")
	}

	path := luks2test.CreateEmptyDiskImage(c, 20)

	options := luks2.FormatOptions{KDFOptions: luks2.KDFOptions{MemoryKiB: 32, ForceIterations: 4}}
	c.Check(luks2.Format(path, "", make([]byte, 32), &options), IsNil)

	createToken := &RecoveryToken{
		TokenBase: TokenBase{
			TokenName:     "recovery",
			TokenKeyslots: []int{0}}}
	c.Check(luks2.ImportToken(path, createToken, nil), IsNil)

	header, err := luks2.ReadHeader(path, luks2.LockModeNonBlocking)
	c.Assert(err, IsNil)

	token, ok := header.Metadata.Tokens[0].(*RecoveryToken)
	c.Assert(ok, testutil.IsTrue)
	c.Check(token, DeepEquals, createToken)
}

func (s *tokenSuite) checkKeyDataTokenJSON(c *C, data []byte, token *KeyDataToken) {
	var j map[string]interface{}
	c.Assert(json.Unmarshal(data, &j), IsNil)

	s.checkTokenBaseJSON(c, j, &token.TokenBase, KeyDataTokenType)

	priority, ok := j["ubuntu_fde_priority"].(float64)
	c.Check(ok, testutil.IsTrue)
	c.Check(priority, Equals, float64(token.Priority))

	if len(token.Data) == 0 {
		c.Check(j, Not(testutil.HasKey), "ubuntu_fde_data")
	} else {
		var expectedData map[string]interface{}
		c.Assert(json.Unmarshal(token.Data, &expectedData), IsNil)

		d, ok := j["ubuntu_fde_data"]
		c.Check(ok, testutil.IsTrue)
		c.Check(d, DeepEquals, expectedData)
	}
}

func (s *tokenSuite) TestMarshalKeyDataToken1(c *C) {
	token := &KeyDataToken{
		TokenBase: TokenBase{
			TokenName:     "foo",
			TokenKeyslots: []int{0}},
		Priority: 1}
	data, err := json.Marshal(token)
	c.Check(err, IsNil)

	s.checkKeyDataTokenJSON(c, data, token)
}

func (s *tokenSuite) TestMarshalKeyDataToken2(c *C) {
	token := &KeyDataToken{
		TokenBase: TokenBase{
			TokenName:     "bar",
			TokenKeyslots: []int{3}},
		Priority: 2,
		Data:     json.RawMessage(`{"key1":"foo","key2":542}`)}
	data, err := json.Marshal(token)
	c.Check(err, IsNil)

	s.checkKeyDataTokenJSON(c, data, token)
}

func (s *tokenSuite) TestUnmarshalKeyDataToken1(c *C) {
	token := &KeyDataToken{
		TokenBase: TokenBase{
			TokenName:     "foo",
			TokenKeyslots: []int{0}},
		Priority: 1}
	data, err := json.Marshal(token)
	c.Check(err, IsNil)

	var token2 *KeyDataToken
	c.Check(json.Unmarshal(data, &token2), IsNil)
	c.Check(token2, DeepEquals, token)
}

func (s *tokenSuite) TestUnmarshalKeyDataToken2(c *C) {
	token := &KeyDataToken{
		TokenBase: TokenBase{
			TokenName:     "bar",
			TokenKeyslots: []int{3}},
		Priority: 2,
		Data:     json.RawMessage(`{"key1":"foo","key2":542}`)}
	data, err := json.Marshal(token)
	c.Check(err, IsNil)

	var token2 *KeyDataToken
	c.Check(json.Unmarshal(data, &token2), IsNil)
	c.Check(token2, DeepEquals, token)
	c.Logf("%s\n", token2.Data)
}

func (s *tokenSuite) TestDecodeKeyDataToken(c *C) {
	if luks2.DetectCryptsetupFeatures()&luks2.FeatureTokenImport == 0 {
		c.Skip("cryptsetup doesn't support token import")
	}

	path := luks2test.CreateEmptyDiskImage(c, 20)

	options := luks2.FormatOptions{KDFOptions: luks2.KDFOptions{MemoryKiB: 32, ForceIterations: 4}}
	c.Check(luks2.Format(path, "", make([]byte, 32), &options), IsNil)

	createToken := &KeyDataToken{
		TokenBase: TokenBase{
			TokenName:     "bar",
			TokenKeyslots: []int{0}},
		Priority: 2,
		Data:     json.RawMessage(`{"key1":"foo","key2":542}`)}
	c.Check(luks2.ImportToken(path, createToken, nil), IsNil)

	header, err := luks2.ReadHeader(path, luks2.LockModeNonBlocking)
	c.Assert(err, IsNil)

	token, ok := header.Metadata.Tokens[0].(*KeyDataToken)
	c.Assert(ok, testutil.IsTrue)
	c.Check(token, DeepEquals, createToken)
}

var testHeader = luks2.HeaderInfo{
	Metadata: luks2.Metadata{
		Keyslots: map[int]*luks2.Keyslot{
			0: new(luks2.Keyslot),
			1: new(luks2.Keyslot),
			2: new(luks2.Keyslot),
			3: new(luks2.Keyslot),
			4: new(luks2.Keyslot),
			5: new(luks2.Keyslot)},
		Tokens: map[int]luks2.Token{
			0: &KeyDataToken{
				TokenBase: TokenBase{
					TokenKeyslots: []int{0},
					TokenName:     "foo"},
				Priority: 2},
			1: &RecoveryToken{
				TokenBase: TokenBase{
					TokenKeyslots: []int{1},
					TokenName:     "recovery"}},
			2: &KeyDataToken{
				TokenBase: TokenBase{
					TokenKeyslots: []int{2},
					TokenName:     "bar"},
				Priority: 1},
			// Test that this token type is ignored.
			3: &luks2.GenericToken{
				TokenType:     "luks2-keyring",
				TokenKeyslots: []int{3}},
			// Add another token with the same priority as
			// an existing one to check that the behaviour of
			// CurrentTokensByPriority is well defined.
			4: &KeyDataToken{
				TokenBase: TokenBase{
					TokenKeyslots: []int{4},
					TokenName:     "abc"},
				Priority: 2},
			// Add a token with priority 0 to test that it
			// is omitted from CurrentTokensByPriority.
			5: &KeyDataToken{
				TokenBase: TokenBase{
					TokenKeyslots: []int{5},
					TokenName:     "xyz"},
				Priority: 0},
			// Add a token without a corresponding keyslot
			// to test AllOrphanedTokenIds, and to ensure that
			// it is omitted from CurrentTokensByPriority.
			6: &KeyDataToken{
				TokenBase: TokenBase{
					TokenName: "orphaned"},
				Priority: 10},
			// Add a token with an invalid keyslots field to
			// make sure that it is ignored.
			7: &KeyDataToken{
				TokenBase: TokenBase{
					TokenKeyslots: []int{0, 1},
					TokenName:     "invalid-keyslots"},
				Priority: 1},
			// Add a token with an empty name to make sure
			// that it is ignored.
			8: &KeyDataToken{
				TokenBase: TokenBase{
					TokenKeyslots: []int{0}},
				Priority: 1}}}}

func (s *tokenSuite) TestTokenViewListNames(c *C) {
	view, err := NewTokenView(&testHeader)
	c.Assert(err, IsNil)
	c.Check(view.ListNames(), DeepEquals, []string{"abc", "bar", "foo", "recovery", "xyz"})
}

func (s *tokenSuite) TestTokenViewTokenByName1(c *C) {
	view, err := NewTokenView(&testHeader)
	c.Assert(err, IsNil)

	token, id, exists := view.TokenByName("foo")
	c.Check(exists, testutil.IsTrue)
	c.Check(token, DeepEquals, testHeader.Metadata.Tokens[0])
	c.Check(id, Equals, 0)
}

func (s *tokenSuite) TestTokenViewTokenByName2(c *C) {
	view, err := NewTokenView(&testHeader)
	c.Assert(err, IsNil)

	token, id, exists := view.TokenByName("bar")
	c.Check(exists, testutil.IsTrue)
	c.Check(token, DeepEquals, testHeader.Metadata.Tokens[2])
	c.Check(id, Equals, 2)
}

func (s *tokenSuite) TestTokenViewTokenByNonExistant(c *C) {
	view, err := NewTokenView(&testHeader)
	c.Assert(err, IsNil)

	token, _, exists := view.TokenByName("zzz")
	c.Check(exists, Not(testutil.IsTrue))
	c.Check(token, IsNil)
}

func (s *tokenSuite) TestTokenViewNameInUse(c *C) {
	view, err := NewTokenView(&testHeader)
	c.Assert(err, IsNil)

	c.Check(view.NameInUse("foo"), testutil.IsTrue)
}

func (s *tokenSuite) TestTokenViewNameNotInUse(c *C) {
	view, err := NewTokenView(&testHeader)
	c.Assert(err, IsNil)

	c.Check(view.NameInUse("zzz"), Not(testutil.IsTrue))
}

func (s *tokenSuite) TestTokenViewKeyDataTokensByPriority(c *C) {
	view, err := NewTokenView(&testHeader)
	c.Assert(err, IsNil)

	tokens := view.KeyDataTokensByPriority()
	c.Assert(tokens, HasLen, 3)
	c.Check(tokens[0], DeepEquals, testHeader.Metadata.Tokens[4])
	c.Check(tokens[1], DeepEquals, testHeader.Metadata.Tokens[0])
	c.Check(tokens[2], DeepEquals, testHeader.Metadata.Tokens[2])
}

func (s *tokenSuite) TestTokenViewOrphanedTokenIds(c *C) {
	view, err := NewTokenView(&testHeader)
	c.Assert(err, IsNil)
	c.Check(view.OrphanedTokenIds(), DeepEquals, []int{6})
}
