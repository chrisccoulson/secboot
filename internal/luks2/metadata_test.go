// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2020 Canonical Ltd
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

package luks2_test

import (
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	. "github.com/snapcore/secboot/internal/luks2"
	"github.com/snapcore/secboot/internal/testutil"
	snapd_testutil "github.com/snapcore/snapd/testutil"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"
)

type metadataSuite struct {
	snapd_testutil.BaseTest
	runDir string
}

func (s *metadataSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)

	s.runDir = c.MkDir()
	s.AddCleanup(MockRunDir(s.runDir))
}

func (s *metadataSuite) decompress(c *C, path string) string {
	dir := c.MkDir()
	name := filepath.Base(path)
	dst := filepath.Join(dir, name)
	c.Assert(testutil.CopyFile(dst+".xz", path+".xz", 0600), IsNil)
	c.Assert(exec.Command("unxz", dst+".xz").Run(), IsNil)
	return dst
}

var _ = Suite(&metadataSuite{})

func (s *metadataSuite) TestAcquireSharedLockOnFile(c *C) {
	path := filepath.Join(c.MkDir(), "disk")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	release, err := AcquireSharedLock(path, LockModeBlocking)
	c.Assert(err, IsNil)

	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Check(err, ErrorMatches, "resource temporarily unavailable")

	err = unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB)
	c.Check(err, IsNil)

	release()

	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Check(err, IsNil)
}

func (s *metadataSuite) TestTryAcquireSharedLockOnFile(c *C) {
	path := filepath.Join(c.MkDir(), "disk")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Assert(err, IsNil)

	_, err = AcquireSharedLock(path, LockModeNonBlocking)
	c.Check(err, ErrorMatches, "cannot obtain lock: resource temporarily unavailable")

	err = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	c.Assert(err, IsNil)

	release, err := AcquireSharedLock(path, LockModeNonBlocking)
	c.Assert(err, IsNil)
	release()
}

func (s *metadataSuite) TestAcquireSharedLockOnUnsupportedFile(c *C) {
	_, err := AcquireSharedLock("/dev/null", LockModeBlocking)
	c.Check(err, ErrorMatches, "unsupported file type")
}

func (s *metadataSuite) TestAcquireSharedLockOnDevice(c *C) {
	restore := MockDataDeviceInfo(&unix.Stat_t{Mode: unix.S_IFBLK | 0600, Rdev: unix.Mkdev(8, 0)})
	defer restore()

	path := filepath.Join(c.MkDir(), "disk")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	release, err := AcquireSharedLock(path, LockModeBlocking)
	c.Assert(err, IsNil)
	defer release()

	lockPath := filepath.Join(s.runDir, "cryptsetup", "L_8:0")
	lockFile, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	c.Assert(err, IsNil)
	defer lockFile.Close()

	err = unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Check(err, ErrorMatches, "resource temporarily unavailable")

	err = unix.Flock(int(lockFile.Fd()), unix.LOCK_SH|unix.LOCK_NB)
	c.Check(err, IsNil)

	err = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
	c.Assert(err, IsNil)

	release()

	err = unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Check(err, IsNil)

	_, err = os.Open(lockPath)
	c.Check(err, ErrorMatches, ".*: no such file or directory")
}

func (s *metadataSuite) TestAcquireSharedLockOnDeviceNoCleanup(c *C) {
	restore := MockDataDeviceInfo(&unix.Stat_t{Mode: unix.S_IFBLK | 0600, Rdev: unix.Mkdev(8, 0)})
	defer restore()

	path := filepath.Join(c.MkDir(), "disk")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	release, err := AcquireSharedLock(path, LockModeBlocking)
	c.Assert(err, IsNil)
	defer release()

	lockPath := filepath.Join(s.runDir, "cryptsetup", "L_8:0")
	lockFile, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	c.Assert(err, IsNil)
	defer lockFile.Close()

	err = unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Check(err, ErrorMatches, "resource temporarily unavailable")

	err = unix.Flock(int(lockFile.Fd()), unix.LOCK_SH|unix.LOCK_NB)
	c.Check(err, IsNil)

	release()

	err = unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Check(err, IsNil)

	lockFile, err = os.Open(lockPath)
	c.Assert(err, IsNil)
	defer lockFile.Close()
}

func (s *metadataSuite) TestAcquireSharedLockOnDeviceWithExistingLockDir(c *C) {
	restore := MockDataDeviceInfo(&unix.Stat_t{Mode: unix.S_IFBLK | 0600, Rdev: unix.Mkdev(8, 0)})
	defer restore()

	c.Assert(os.Mkdir(filepath.Join(s.runDir, "cryptsetup"), 0700), IsNil)

	path := filepath.Join(c.MkDir(), "disk")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	release, err := AcquireSharedLock(path, LockModeBlocking)
	c.Assert(err, IsNil)
	defer release()

	lockPath := filepath.Join(s.runDir, "cryptsetup", "L_8:0")
	lockFile, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	c.Assert(err, IsNil)
	defer lockFile.Close()
}

func (s *metadataSuite) TestAcquireManySharedLocksOnDevice(c *C) {
	restore := MockDataDeviceInfo(&unix.Stat_t{Mode: unix.S_IFBLK | 0600, Rdev: unix.Mkdev(8, 0)})
	defer restore()

	path := filepath.Join(c.MkDir(), "disk")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	var wg sync.WaitGroup

	routine := func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			release, err := AcquireSharedLock(path, LockModeBlocking)
			c.Assert(err, IsNil)
			time.Sleep(time.Duration(rand.Intn(15000)) * time.Microsecond)
			release()
		}
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go routine()
	}

	wg.Wait()

	lockPath := filepath.Join(s.runDir, "cryptsetup", "L_8:0")
	_, err = os.Open(lockPath)
	c.Check(err, ErrorMatches, ".*: no such file or directory")
}

type testDecodeHdrData struct {
	path         string
	hdrSize      uint64
	keyslotsSize uint64
}

func (s *metadataSuite) testDecodeHdr(c *C, data *testDecodeHdrData) {
	hdr, err := DecodeHdr(s.decompress(c, data.path), LockModeBlocking)
	c.Assert(err, IsNil)

	c.Check(hdr.HdrSize, Equals, data.hdrSize)
	c.Check(hdr.Label, Equals, "data")

	c.Assert(hdr.Metadata.Keyslots, HasLen, 2)

	c.Check(hdr.Metadata.Keyslots[0].Type, Equals, KeyslotTypeLUKS2)
	c.Check(hdr.Metadata.Keyslots[0].KeySize, Equals, 64)
	c.Assert(hdr.Metadata.Keyslots[0].Area, NotNil)
	c.Check(hdr.Metadata.Keyslots[0].Area.Type, Equals, AreaTypeRaw)
	c.Check(hdr.Metadata.Keyslots[0].Area.Offset, Equals, data.hdrSize*2)
	c.Check(hdr.Metadata.Keyslots[0].Area.Size, Equals, uint64(258048))
	c.Check(hdr.Metadata.Keyslots[0].Area.Encryption, Equals, "aes-xts-plain64")
	c.Check(hdr.Metadata.Keyslots[0].Area.KeySize, Equals, 64)
	c.Assert(hdr.Metadata.Keyslots[0].KDF, NotNil)
	c.Check(hdr.Metadata.Keyslots[0].KDF.Type, Equals, KDFTypeArgon2i)
	c.Check(hdr.Metadata.Keyslots[0].KDF.Salt, HasLen, 32)
	c.Assert(hdr.Metadata.Keyslots[0].AF, NotNil)
	c.Check(hdr.Metadata.Keyslots[0].AF.Type, Equals, AFTypeLUKS1)
	c.Check(hdr.Metadata.Keyslots[0].AF.Stripes, Equals, 4000)
	c.Check(hdr.Metadata.Keyslots[0].AF.Hash, Equals, HashSHA256)
	c.Check(hdr.Metadata.Keyslots[0].Priority, Equals, SlotPriorityHigh)

	c.Check(hdr.Metadata.Keyslots[1].Type, Equals, KeyslotTypeLUKS2)
	c.Check(hdr.Metadata.Keyslots[1].KeySize, Equals, 64)
	c.Assert(hdr.Metadata.Keyslots[1].Area, NotNil)
	c.Check(hdr.Metadata.Keyslots[1].Area.Type, Equals, AreaTypeRaw)
	c.Check(hdr.Metadata.Keyslots[1].Area.Offset, Equals, (data.hdrSize*2)+258048)
	c.Check(hdr.Metadata.Keyslots[1].Area.Size, Equals, uint64(258048))
	c.Check(hdr.Metadata.Keyslots[1].Area.Encryption, Equals, "aes-xts-plain64")
	c.Check(hdr.Metadata.Keyslots[1].Area.KeySize, Equals, 64)
	c.Assert(hdr.Metadata.Keyslots[1].KDF, NotNil)
	c.Check(hdr.Metadata.Keyslots[1].KDF.Type, Equals, KDFTypePBKDF2)
	c.Check(hdr.Metadata.Keyslots[1].KDF.Salt, HasLen, 32)
	c.Check(hdr.Metadata.Keyslots[1].KDF.Hash, Equals, HashSHA256)
	c.Assert(hdr.Metadata.Keyslots[1].AF, NotNil)
	c.Check(hdr.Metadata.Keyslots[1].AF.Type, Equals, AFTypeLUKS1)
	c.Check(hdr.Metadata.Keyslots[1].AF.Stripes, Equals, 4000)
	c.Check(hdr.Metadata.Keyslots[1].AF.Hash, Equals, HashSHA256)
	c.Check(hdr.Metadata.Keyslots[1].Priority, Equals, SlotPriorityNormal)

	c.Assert(hdr.Metadata.Segments, HasLen, 1)
	c.Check(hdr.Metadata.Segments[0].Type, Equals, "crypt")
	c.Check(hdr.Metadata.Segments[0].Offset, Equals, uint64(0))
	c.Check(hdr.Metadata.Segments[0].DynamicSize, Equals, true)
	c.Check(hdr.Metadata.Segments[0].Encryption, Equals, "aes-xts-plain64")
	c.Check(hdr.Metadata.Segments[0].SectorSize, Equals, 512)
	c.Check(hdr.Metadata.Segments[0].Integrity, IsNil)

	c.Assert(hdr.Metadata.Tokens, HasLen, 1)
	c.Check(hdr.Metadata.Tokens[0].Type, Equals, "secboot-test")
	c.Check(hdr.Metadata.Tokens[0].Keyslots, DeepEquals, []int{0})
	c.Check(hdr.Metadata.Tokens[0].Params, DeepEquals, map[string]interface{}{"secboot-a": "foo", "secboot-b": float64(7)})

	c.Assert(hdr.Metadata.Digests, HasLen, 1)
	c.Check(hdr.Metadata.Digests[0].Type, Equals, KDFTypePBKDF2)
	c.Check(hdr.Metadata.Digests[0].Keyslots, DeepEquals, []int{0, 1})
	c.Check(hdr.Metadata.Digests[0].Segments, DeepEquals, []int{0})
	c.Check(hdr.Metadata.Digests[0].Salt, HasLen, 32)
	c.Check(hdr.Metadata.Digests[0].Digest, HasLen, 32)
	c.Check(hdr.Metadata.Digests[0].Hash, Equals, HashSHA256)

	c.Check(hdr.Metadata.Config.JSONSize, Equals, data.hdrSize-4096)
	c.Check(hdr.Metadata.Config.KeyslotsSize, Equals, data.keyslotsSize)
}

func (s *metadataSuite) TestDecodeHdrValid(c *C) {
	// Test a valid header
	s.testDecodeHdr(c, &testDecodeHdrData{
		path:         "testdata/luks2-valid-hdr.img",
		hdrSize:      16384,
		keyslotsSize: 16744448,
	})
}

func (s *metadataSuite) TestDecodeHdrInvalidPrimary(c *C) {
	// Test where the primary header has an invalid checksum. The primary header has an
	// invalid JSON size, so the test will fail if the secondary header isn't selected.
	s.testDecodeHdr(c, &testDecodeHdrData{
		path:         "testdata/luks2-hdr-invalid-checksum0.img",
		hdrSize:      16384,
		keyslotsSize: 16744448,
	})
}

func (s *metadataSuite) TestDecodeHdrInvalidSecondary(c *C) {
	// Test where the secondary header has an invalid checksum. The secondary header has an
	// invalid JSON size, so the test will fail if the primary header isn't selected.
	s.testDecodeHdr(c, &testDecodeHdrData{
		path:         "testdata/luks2-hdr-invalid-checksum1.img",
		hdrSize:      16384,
		keyslotsSize: 16744448,
	})
}

func (s *metadataSuite) TestDecodeHdrCustomMetadataSize(c *C) {
	// Test a valid header with different metadata and binary keyslot area sizes
	s.testDecodeHdr(c, &testDecodeHdrData{
		path:         "testdata/luks2-valid-hdr2.img",
		hdrSize:      65536,
		keyslotsSize: 8257536,
	})
}

func (s *metadataSuite) TestDecodeHdrCustomMetadataSizeInvalidPrimary(c *C) {
	// Test a valid header with different metadata and binary keyslot area sizes. The
	// primary header has an invalid checksum because of an invalid JSON size, so the
	// test will fail if the secondary header isn't selected.
	s.testDecodeHdr(c, &testDecodeHdrData{
		path:         "testdata/luks2-hdr2-invalid-checksum0.img",
		hdrSize:      65536,
		keyslotsSize: 8257536,
	})
}

func (s *metadataSuite) TestDecodeHdrInvalidMagic(c *C) {
	// Test where both headers have invalid magic values to check we get the right error.
	_, err := DecodeHdr(s.decompress(c, "testdata/luks2-hdr-invalid-magic-both.img"), LockModeBlocking)
	c.Check(err, ErrorMatches, "no valid header found, error from decoding primary header: invalid magic")
}

func (s *metadataSuite) TestDecodeHdrInvalidVersion(c *C) {
	// Test where both headers have an invalid version to check we get the right error.
	_, err := DecodeHdr(s.decompress(c, "testdata/luks2-hdr-invalid-version-both.img"), LockModeBlocking)
	c.Check(err, ErrorMatches, "no valid header found, error from decoding primary header: invalid version")
}
