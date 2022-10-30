// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

import (
	"io"

	"golang.org/x/xerrors"
)

// Write writes the event log to w in a format that can be read again
// by ReadLog. If the log is a crypto-agile log, each of the supplied
// events must contain a digest for each algorithm. For a non
// crypto-agile log, each of the events must contain a SHA-1 digest.
func (l *Log) Write(w io.Writer) error {
	if len(l.Events) == 0 {
		return nil
	}

	var cryptoAgile bool
	var digestSizes []EFISpecIdEventAlgorithmSize

	switch d := l.Events[0].Data.(type) {
	case *SpecIdEvent00:
		_ = d
	case *SpecIdEvent02:
		_ = d
	case *SpecIdEvent03:
		cryptoAgile = true
		digestSizes = d.DigestSizes
	}

	if err := l.Events[0].Write(w); err != nil {
		return xerrors.Errorf("cannot write event 0: %w", err)
	}

	for i, event := range l.Events[1:] {
		if cryptoAgile {
			if err := event.WriteCryptoAgile(w, digestSizes); err != nil {
				return xerrors.Errorf("cannot write event %d: %w", i+1, err)
			}
		} else {
			if err := event.Write(w); err != nil {
				return xerrors.Errorf("cannot write event %d: %w", i+1, err)
			}
		}
	}

	return nil
}
