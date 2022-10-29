// Copyright 2019-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

	. "gopkg.in/check.v1"

	. "github.com/canonical/tcglog-parser"
)

type logwriterSuite struct{}

var _ = Suite(&logwriterSuite{})

func (s *logwriterSuite) TestWriteLogCryptoAgile(c *C) {
	f, err := os.Open(filepath.Join("testdata/binary_bios_measurements"))
	c.Assert(err, IsNil)
	defer f.Close()

	expected := new(bytes.Buffer)
	r := io.TeeReader(f, expected)

	log, err := ReadLog(r, &LogOptions{})
	c.Assert(err, IsNil)

	w := new(bytes.Buffer)
	c.Check(log.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, expected.Bytes())
}
