// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package ioerr_test

import (
	"errors"
	"io"
	"testing"

	"golang.org/x/xerrors"

	. "gopkg.in/check.v1"

	. "github.com/canonical/tcglog-parser/internal/ioerr"
)

func Test(t *testing.T) { TestingT(t) }

type ioerrSuite struct{}

var _ = Suite(&ioerrSuite{})

func (s *ioerrSuite) TestEOFIsUnexpectedWithEOFAndWithFormatString(c *C) {
	err := EOFIsUnexpected("foo: %w", io.EOF)
	c.Check(err, ErrorMatches, "foo: unexpected EOF")
	c.Check(xerrors.Is(err, io.ErrUnexpectedEOF), Equals, true)
}

func (s *ioerrSuite) TestEOFIsUnexpectedWithoutEOFAndWithFormatString(c *C) {
	err1 := errors.New("bar")
	err2 := EOFIsUnexpected("foo: %w", err1)
	c.Check(err2, ErrorMatches, "foo: bar")
	c.Check(xerrors.Is(err2, err1), Equals, true)
}

func (s *ioerrSuite) TestEOFIsUnexpectedWithEOFAndWithFormatString2(c *C) {
	err := EOFIsUnexpected("foo %w %d", io.EOF, 5)
	c.Check(err, ErrorMatches, "foo unexpected EOF 5: unexpected EOF")
	c.Check(xerrors.Is(err, io.ErrUnexpectedEOF), Equals, true)
}

func (s *ioerrSuite) TestEOFIsUnexpectedWithoutEOFAndWithFormatString2(c *C) {
	err1 := errors.New("bar")
	err2 := EOFIsUnexpected("foo %w %d", err1, 5)
	c.Check(err2, ErrorMatches, "foo bar 5: bar")
	c.Check(xerrors.Is(err2, err1), Equals, true)
}

func (s *ioerrSuite) TestEOFIsUnexpectedWithEOF(c *C) {
	c.Check(EOFIsUnexpected(io.EOF), Equals, io.ErrUnexpectedEOF)
}

func (s *ioerrSuite) TestEOFIsUnexpectedWithoutEOF(c *C) {
	err1 := errors.New("foo")
	c.Check(EOFIsUnexpected(err1), Equals, err1)
}

func (s *ioerrSuite) TestEOFIsUnexpectedWithNil(c *C) {
	c.Check(EOFIsUnexpected(nil), IsNil)
}

func (s *ioerrSuite) TestPassRawEOFWithEOF(c *C) {
	c.Check(PassRawEOF("foo: %w", io.EOF), Equals, io.EOF)
}

func (s *ioerrSuite) TestPassRawEOFWithoutEOF(c *C) {
	err1 := errors.New("bar")
	err2 := PassRawEOF("foo: %w", err1)
	c.Check(err2, ErrorMatches, "foo: bar")
	c.Check(xerrors.Is(err2, err1), Equals, true)
}
