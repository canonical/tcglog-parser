// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

type Formatter interface {
	PrintHeader()
	PrintEvent(event *Event)
	Flush()
}
