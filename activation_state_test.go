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

package secboot_test

import (
	"encoding/json"
	"math/rand"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
)

type activationStateSuite struct{}

func (s *activationStateSuite) randomKeyID() KeyID {
	id := make(KeyID, 32)
	rand.Read(id)
	return id
}

var _ = Suite(&activationStateSuite{})

func (s *activationStateSuite) TestRecordActivationSuccess1(c *C) {
	state := new(ActivationState)
	id := s.randomKeyID()
	state.RecordActivationSuccess("data", "/dev/sda1", id)

	result := state.LookupResultByVolumeName("data")
	c.Assert(result, NotNil)
	c.Check(result.SourceDevicePath, Equals, "/dev/sda1")
	c.Check(result.VolumeName, Equals, "data")
	c.Check(result.Key, DeepEquals, id)
	c.Check(result.FailedAttempts, HasLen, 0)
}

func (s *activationStateSuite) TestRecordActivationSuccess2(c *C) {
	state := new(ActivationState)

	id1 := s.randomKeyID()
	state.RecordActivationSuccess("data", "/dev/sda1", id1)

	id2 := s.randomKeyID()
	state.RecordActivationSuccess("save", "/dev/sda2", id2)

	result := state.LookupResultByVolumeName("data")
	c.Assert(result, NotNil)
	c.Check(result.SourceDevicePath, Equals, "/dev/sda1")
	c.Check(result.VolumeName, Equals, "data")
	c.Check(result.Key, DeepEquals, id1)
	c.Check(result.FailedAttempts, HasLen, 0)

	result = state.LookupResultByVolumeName("save")
	c.Assert(result, NotNil)
	c.Check(result.SourceDevicePath, Equals, "/dev/sda2")
	c.Check(result.VolumeName, Equals, "save")
	c.Check(result.Key, DeepEquals, id2)
	c.Check(result.FailedAttempts, HasLen, 0)
}

func (s *activationStateSuite) TestRecordActivationFailure1(c *C) {
	state := new(ActivationState)
	id := s.randomKeyID()
	state.RecordActivationFailure("data", "/dev/sda1", id, ActivationErrorInvalidKeyData)

	result := state.LookupResultByVolumeName("data")
	c.Assert(result, NotNil)
	c.Check(result.SourceDevicePath, Equals, "/dev/sda1")
	c.Check(result.VolumeName, Equals, "data")
	c.Check(result.Key, HasLen, 0)

	c.Check(result.FailedAttempts, HasLen, 1)
	c.Check(result.FailedAttempts[0].Key, DeepEquals, id)
	c.Check(result.FailedAttempts[0].Error, Equals, ActivationErrorInvalidKeyData)
}

func (s *activationStateSuite) TestRecordActivationFailureAndThenSuccess(c *C) {
	state := new(ActivationState)

	id1 := s.randomKeyID()
	state.RecordActivationFailure("data", "/dev/sda1", id1, ActivationErrorCryptsetup)

	id2 := s.randomKeyID()
	state.RecordActivationSuccess("data", "/dev/sda1", id2)

	result := state.LookupResultByVolumeName("data")
	c.Assert(result, NotNil)
	c.Check(result.SourceDevicePath, Equals, "/dev/sda1")
	c.Check(result.VolumeName, Equals, "data")
	c.Check(result.Key, DeepEquals, id2)

	c.Check(result.FailedAttempts, HasLen, 1)
	c.Check(result.FailedAttempts[0].Key, DeepEquals, id1)
	c.Check(result.FailedAttempts[0].Error, Equals, ActivationErrorCryptsetup)
}

func (s *activationStateSuite) TestNonExistantVolume(c *C) {
	state := new(ActivationState)
	c.Check(state.LookupResultByVolumeName("data"), IsNil)
}

func (s *activationStateSuite) TestMarshalAndUnmarshalJSON(c *C) {
	state := new(ActivationState)

	id1 := KeyID(testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"))
	state.RecordActivationFailure("data", "/dev/sda1", id1, ActivationErrorInvalidKeyData)

	id2 := KeyID(testutil.DecodeHexString(c, "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730"))
	state.RecordActivationSuccess("data", "/dev/sda1", id2)

	id3 := KeyID(testutil.DecodeHexString(c, "bf07a7fbb825fc0aae7bf4a1177b2b31fcf8a3feeaf7092761e18c859ee52a9c"))
	state.RecordActivationSuccess("save", "/dev/sda2", id3)

	data, err := json.Marshal(state)
	c.Check(err, IsNil)
	c.Check(string(data), Equals, "["+
		"{"+
		"\"source-device-path\":\"/dev/sda1\","+
		"\"volume-name\":\"data\","+
		"\"key\":\"fYZelZskZpGMmGOvypQtD7idfJrAyZuvw3SVBN7ZdzA=\","+
		"\"failed-attempts\":["+
		"{"+
		"\"key\":\"tbudgBSg+bHWHiHnlteNzN8TUvI80ygS9IULh4rklEw=\","+
		"\"error\":\"invalid-key-data\""+
		"}"+
		"]"+
		"},{"+
		"\"source-device-path\":\"/dev/sda2\","+
		"\"volume-name\":\"save\","+
		"\"key\":\"vwen+7gl/Aque/ShF3srMfz4o/7q9wknYeGMhZ7lKpw=\","+
		"\"failed-attempts\":null"+
		"}"+
		"]")

	var state2 *ActivationState
	c.Check(json.Unmarshal(data, &state2), IsNil)
	c.Check(state2, DeepEquals, state)
}
