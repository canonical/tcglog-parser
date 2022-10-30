// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

import (
	"github.com/canonical/go-tpm2"
)

func isSpecIdEvent(event *Event) bool {
	if event.PCRIndex != 0 {
		return false
	}
	if event.EventType != EventTypeNoAction {
		return false
	}

	switch d := event.Data.(type) {
	case *SpecIdEvent00:
		_ = d
		return true
	case *SpecIdEvent02:
		_ = d
		return true
	case *SpecIdEvent03:
		_ = d
		return true
	default:
		return false
	}
}

// DiscardPCRsExcept deletes all events that don't correspond to the
// specified list of PCRs, unless the event is the Spec ID event. This
// is useful for retaining or transmitting only the parts of a log that
// are relevant to the specific application.
func (l *Log) DiscardPCRsExcept(keepPcrs ...PCRIndex) {
	var events []*Event
	for _, e := range l.Events {
		keep := false
		if isSpecIdEvent(e) {
			keep = true
		} else {
			for _, p := range keepPcrs {
				if e.PCRIndex == p {
					keep = true
					break
				}
			}
		}
		if !keep {
			continue
		}

		events = append(events, e)
	}

	l.Events = events
}

// DiscardAlgorithmsExcept deletes all digests except for the ones
// associated with the specified algorithms, unless the event is the
// Spec ID event. This is useful for retaining or transmitting a log
// that only contains digests that are relevant to the specific
// application.
func (l *Log) DiscardAlgorithmsExcept(keepAlgs ...tpm2.HashAlgorithmId) {
	for _, e := range l.Events {
		for a := range e.Digests {
			keep := false
			if isSpecIdEvent(e) && a == tpm2.HashAlgorithmSHA1 {
				keep = true
			} else {
				for _, alg := range keepAlgs {
					if alg == a {
						keep = true
						break
					}
				}
			}
			if keep {
				continue
			}

			delete(e.Digests, a)
		}
	}
}
