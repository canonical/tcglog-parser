// Copyright 2019-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/canonical/go-tpm2"

	"golang.org/x/xerrors"

	"github.com/canonical/tcglog-parser/internal/ioerr"
)

type eventHeader struct {
	PCRIndex  PCRIndex
	EventType EventType
}

type eventHeaderCryptoAgile struct {
	eventHeader
	Count uint32
}

// Event corresponds to a single event in an event log.
type Event struct {
	PCRIndex  PCRIndex  // PCR index to which this event was measured
	EventType EventType // The type of this event
	Digests   DigestMap // The digests corresponding to this event for the supported algorithms
	Data      EventData // The data recorded with this event
}

// Write serializes this event in non crypto-agile form to w. If the event
// does not contain a SHA-1 digest of the correct size, or it contains
// more than one digest, an error will be returned.
func (e *Event) Write(w io.Writer) error {
	digest, ok := e.Digests[tpm2.HashAlgorithmSHA1]
	if !ok {
		return errors.New("missing SHA-1 digest")
	}
	if len(e.Digests) != 1 {
		return errors.New("invalid number of digests")
	}
	if len(digest) != tpm2.HashAlgorithmSHA1.Size() {
		return errors.New("invalid digest size")
	}

	data := new(bytes.Buffer)
	if err := e.Data.Write(data); err != nil {
		return xerrors.Errorf("cannot serialize event data: %w", err)
	}

	hdr := eventHeader{
		PCRIndex:  e.PCRIndex,
		EventType: e.EventType}
	if err := binary.Write(w, binary.LittleEndian, &hdr); err != nil {
		return err
	}

	if _, err := w.Write(digest); err != nil {
		return err
	}

	if err := binary.Write(w, binary.LittleEndian, uint32(data.Len())); err != nil {
		return err
	}
	_, err := w.Write(data.Bytes())
	return err
}

// WriteCryptoAgile serializes this even in crypto-agile form to w. If the
// event does not contain a digest of the correct size for each entry in
// digestSizes, or it contains more digests, an error will be returned.
func (e *Event) WriteCryptoAgile(w io.Writer, digestSizes []EFISpecIdEventAlgorithmSize) error {
	if len(e.Digests) != len(digestSizes) {
		return errors.New("invalid number of digests")
	}
	for _, d := range digestSizes {
		digest, ok := e.Digests[d.AlgorithmId]
		if !ok {
			return fmt.Errorf("missing %v digest", d.AlgorithmId)
		}
		if len(digest) != int(d.DigestSize) {
			return fmt.Errorf("invalid digest size for %v", d.AlgorithmId)
		}
	}

	data := new(bytes.Buffer)
	if err := e.Data.Write(data); err != nil {
		return xerrors.Errorf("cannot serialize event data: %w", err)
	}

	hdr := eventHeaderCryptoAgile{
		eventHeader: eventHeader{
			PCRIndex:  e.PCRIndex,
			EventType: e.EventType},
		Count: uint32(len(digestSizes))}
	if err := binary.Write(w, binary.LittleEndian, &hdr); err != nil {
		return err
	}

	for _, d := range digestSizes {
		if err := binary.Write(w, binary.LittleEndian, d.AlgorithmId); err != nil {
			return err
		}
		if _, err := w.Write(e.Digests[d.AlgorithmId]); err != nil {
			return err
		}
	}

	if err := binary.Write(w, binary.LittleEndian, uint32(data.Len())); err != nil {
		return err
	}
	_, err := w.Write(data.Bytes())
	return err
}

func isPCRIndexInRange(index PCRIndex) bool {
	const maxPCRIndex PCRIndex = 31
	return index <= maxPCRIndex
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
		if alg.IsValid() {
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
