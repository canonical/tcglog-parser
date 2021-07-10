// Copyright 2019-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/canonical/go-tpm2"

	"github.com/canonical/tcglog-parser/internal/ioerr"
)

// Event corresponds to a single event in an event log.
type Event struct {
	PCRIndex  PCRIndex  // PCR index to which this event was measured
	EventType EventType // The type of this event
	Digests   DigestMap // The digests corresponding to this event for the supported algorithms
	Data      EventData // The data recorded with this event
}

func isPCRIndexInRange(index PCRIndex) bool {
	const maxPCRIndex PCRIndex = 31
	return index <= maxPCRIndex
}

type eventHeader struct {
	PCRIndex  PCRIndex
	EventType EventType
}

func ReadEvent(r io.Reader, options *LogOptions) (*Event, error) {
	var header eventHeader
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, err
	}

	if !isPCRIndexInRange(header.PCRIndex) {
		return nil, fmt.Errorf("log entry has an out-of-range PCR index (%d)", header.PCRIndex)
	}

	digest := make(Digest, tpm2.HashAlgorithmSHA1.Size())
	if _, err := io.ReadFull(r, digest); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	digests := make(DigestMap)
	digests[tpm2.HashAlgorithmSHA1] = digest

	var eventSize uint32
	if err := binary.Read(r, binary.LittleEndian, &eventSize); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	event := make([]byte, eventSize)
	if _, err := io.ReadFull(r, event); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	return &Event{
		PCRIndex:  header.PCRIndex,
		EventType: header.EventType,
		Digests:   digests,
		Data:      decodeEventData(event, header.PCRIndex, header.EventType, digests, options),
	}, nil
}

type eventHeaderCryptoAgile struct {
	eventHeader
	Count uint32
}

func ReadEventCryptoAgile(r io.Reader, digestSizes []EFISpecIdEventAlgorithmSize, options *LogOptions) (*Event, error) {
	var header eventHeaderCryptoAgile
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, err
	}

	if !isPCRIndexInRange(header.PCRIndex) {
		return nil, fmt.Errorf("log entry has an out-of-range PCR index (%d)", header.PCRIndex)
	}

	digests := make(DigestMap)

	for i := uint32(0); i < header.Count; i++ {
		var algorithmId tpm2.HashAlgorithmId
		if err := binary.Read(r, binary.LittleEndian, &algorithmId); err != nil {
			return nil, ioerr.EOFIsUnexpected(err)
		}

		var digestSize uint16
		var j int
		for j = 0; j < len(digestSizes); j++ {
			if digestSizes[j].AlgorithmId == algorithmId {
				digestSize = digestSizes[j].DigestSize
				break
			}
		}

		if j == len(digestSizes) {
			return nil, fmt.Errorf("event contains a digest for an unrecognized algorithm (%v)", algorithmId)
		}

		digest := make(Digest, digestSize)
		if _, err := io.ReadFull(r, digest); err != nil {
			return nil, ioerr.EOFIsUnexpected("cannot read digest for algorithm %v: %w", algorithmId, err)
		}

		if _, exists := digests[algorithmId]; exists {
			return nil, fmt.Errorf("event contains more than one digest value for algorithm %v", algorithmId)
		}
		digests[algorithmId] = digest
	}

	for _, s := range digestSizes {
		if _, exists := digests[s.AlgorithmId]; !exists {
			return nil, fmt.Errorf("event is missing a digest value for algorithm %v", s.AlgorithmId)
		}
	}

	for alg, _ := range digests {
		if alg.Supported() {
			continue
		}
		delete(digests, alg)
	}

	var eventSize uint32
	if err := binary.Read(r, binary.LittleEndian, &eventSize); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	event := make([]byte, eventSize)
	if _, err := io.ReadFull(r, event); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	return &Event{
		PCRIndex:  header.PCRIndex,
		EventType: header.EventType,
		Digests:   digests,
		Data:      decodeEventData(event, header.PCRIndex, header.EventType, digests, options),
	}, nil
}
