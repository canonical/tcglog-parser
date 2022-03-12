// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package main

import (
	"github.com/canonical/tcglog-parser"
)

type formatter interface {
	printHeader()
	printEvent(event *tcglog.Event)
	flush()
}
