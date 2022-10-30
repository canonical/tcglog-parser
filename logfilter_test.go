// Copyright 2019-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog_test

import (
	"os"
	"path/filepath"

	"github.com/canonical/go-tpm2"

	. "gopkg.in/check.v1"

	. "github.com/canonical/tcglog-parser"
)

type logfilterSuite struct{}

var _ = Suite(&logfilterSuite{})

func (s *logfilterSuite) TestFilterLogPCRs(c *C) {
	f, err := os.Open(filepath.Join("testdata/binary_bios_measurements"))
	c.Assert(err, IsNil)
	defer f.Close()

	log, err := ReadLog(f, &LogOptions{})
	c.Assert(err, IsNil)

	log.DiscardPCRsExcept(2, 4)
	c.Check(log.Events, HasLen, 6)

	c.Check(log.Events[0].PCRIndex, Equals, PCRIndex(0))
	for _, e := range log.Events[1:] {
		c.Check(e.PCRIndex == 2 || e.PCRIndex == 4, Equals, true)
	}
}

func (s *logfilterSuite) TestFilterLogAlgorithms(c *C) {
	f, err := os.Open(filepath.Join("testdata/binary_bios_measurements"))
	c.Assert(err, IsNil)
	defer f.Close()

	log, err := ReadLog(f, &LogOptions{})
	c.Assert(err, IsNil)

	log.DiscardAlgorithmsExcept(tpm2.HashAlgorithmSHA256)

	checkEvent := func(e *Event, algs ...tpm2.HashAlgorithmId) bool {
		if len(e.Digests) != len(algs) {
			return false
		}
		for a := range e.Digests {
			found := false
			for _, alg := range algs {
				if alg == a {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}

	c.Check(checkEvent(log.Events[0], tpm2.HashAlgorithmSHA1), Equals, true)
	for _, e := range log.Events[1:] {
		c.Check(checkEvent(e, tpm2.HashAlgorithmSHA256), Equals, true)
	}

}
