// Copyright 2019-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog_test

import (
	"bytes"
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"

	. "gopkg.in/check.v1"

	. "github.com/canonical/tcglog-parser"
)

type sdefistubSuite struct{}

var _ = Suite(&sdefistubSuite{})

func (s *sdefistubSuite) TestComputeSystemdEFIStubCommandlineDigest1(c *C) {
	c.Check(ComputeSystemdEFIStubCommandlineDigest(crypto.SHA256, "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run systemd.debug-shell=1"),
		DeepEquals,
		decodeHexString(c, "b4ac9681749dbf5ba3bd9e0657ec227f840421385e25b8b7a0a4cbeb51a9ed06"))
}

func (s *sdefistubSuite) TestSystemdEFIStubCommandlineWrite(c *C) {
	cmdline := SystemdEFIStubCommandline{Str: "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run systemd.debug-shell=1"}

	w := new(bytes.Buffer)
	c.Check(cmdline.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals,
		decodeHexString(c, "63006f006e0073006f006c0065003d0074007400790053003000200063006f006e0073006f006c0065003d007400740079"+
			"0031002000700061006e00690063003d002d0031002000730079007300740065006d0064002e006700700074005f006100750074006f003d0030002000"+
			"73006e006100700064005f007200650063006f0076006500720079005f006d006f00640065003d00720075006e002000730079007300740065006d0064"+
			"002e00640065006200750067002d007300680065006c006c003d00310000"))
	c.Check(w.Bytes(), HasLen, len(cmdline.Str)*2+1)
}
