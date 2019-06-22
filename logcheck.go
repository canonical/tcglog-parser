package tcglog

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unsafe"
)

type UnexpectedEventTypeReportEntry struct {
	event *Event
}

func (r *UnexpectedEventTypeReportEntry) String() string {
	return fmt.Sprintf("Unexpected %s event type measured to PCR index %d",
		r.event.EventType, r.event.PCRIndex)
}

func (r *UnexpectedEventTypeReportEntry) Event() *Event {
	return r.event
}

type InvalidEventDataReportEntry struct {
	event *Event
	err   error
}

func (r *InvalidEventDataReportEntry) String() string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "Invalid event data for event type %s", r.event.EventType)
	if r.err != nil {
		fmt.Fprintf(&builder, " (%v)", r.err)
	}
	return builder.String()
}

func (r *InvalidEventDataReportEntry) Event() *Event {
	return r.event
}

type UnexpectedDigestValueReportEntry struct {
	event     *Event
	Algorithm AlgorithmId
	Expected  Digest
}

func (r *UnexpectedDigestValueReportEntry) String() string {
	return fmt.Sprintf("Unexpected digest value for event type %s and algorithm %s (got %x, expected %x)",
		r.event.EventType, r.Algorithm, r.event.Digests[r.Algorithm], r.Expected)
}

func (r *UnexpectedDigestValueReportEntry) Event() *Event {
	return r.event
}

type LogCheckReportEntry interface {
	String() string
	Event() *Event
}

type LogCheckReport struct {
	Entries []LogCheckReportEntry
}

func hash(data []byte, alg AlgorithmId) []byte {
	switch alg {
	case AlgorithmSha1:
		h := sha1.Sum(data)
		return h[:]
	case AlgorithmSha256:
		h := sha256.Sum256(data)
		return h[:]
	case AlgorithmSha384:
		h := sha512.Sum384(data)
		return h[:]
	case AlgorithmSha512:
		h := sha512.Sum512(data)
		return h[:]
	default:
		panic("Unhandled algorithm")
	}
}

func isExpectedEventTypeForIndex(t EventType, i PCRIndex, spec Spec) bool {
	if i > 7 {
		return true
	}

	switch t {
	case EventTypePostCode, EventTypeSCRTMContents, EventTypeSCRTMVersion, EventTypeNonhostCode,
		EventTypeNonhostInfo, EventTypeEFIHCRTMEvent:
		return i == 0
	case EventTypeNoAction:
		return i == 0 || i == 6
	case EventTypeAction, EventTypeEFIAction:
		return i >= 1 && i <= 6
	case EventTypeEventTag:
		return i <= 4 && spec <= SpecPCClient
	case EventTypeCPUMicrocode, EventTypePlatformConfigFlags, EventTypeTableOfDevices, EventTypeNonhostConfig,
		EventTypeEFIVariableBoot, EventTypeEFIHandoffTables:
		return i == 1
	case EventTypeCompactHash:
		return i >= 4
	case EventTypeIPL:
		return i == 4 && spec <= SpecPCClient
	case EventTypeIPLPartitionData:
		return i == 5 && spec <= SpecPCClient
	case EventTypeOmitBootDeviceEvents:
		return i == 4
	case EventTypeEFIVariableDriverConfig:
		return i == 1 || i == 3 || i == 5 || i == 7
	case EventTypeEFIBootServicesApplication:
		return i == 2 || i == 4
	case EventTypeEFIBootServicesDriver, EventTypeEFIRuntimeServicesDriver:
		return i == 0 || i == 2
	case EventTypeEFIGPTEvent:
		return i == 5
	case EventTypeEFIPlatformFirmwareBlob:
		return i == 0 || i == 2 || i == 4
	case EventTypeEFIVariableAuthority:
		return i == 7
	default:
		return true
	}
}

func checkEventData(data EventData, t EventType) error {
	switch t {
	case EventTypeSeparator:
		if data.MeasuredBytes() == nil {
			return nil
		}
		s := len(data.RawBytes())
		if s != 4 {
			return fmt.Errorf("unexpected event data size of %d", s)
		}
		for _, v := range separatorEventNormalValues {
			if v == *(*uint32)(unsafe.Pointer(&data.RawBytes()[0])) {
				return nil
			}
		}
		return errors.New("unexpected event data contents")
	case EventTypeCompactHash:
		s := len(data.RawBytes())
		if s == 4 {
			return nil
		}
		return fmt.Errorf("unexpected event data size of %d", s)
	case EventTypeOmitBootDeviceEvents:
		if string(data.RawBytes()) == "BOOT ATTEMPTS OMITTED" {
			return nil
		}
		return errors.New("unexpected event data contents")
	case EventTypeEFIHCRTMEvent:
		if string(data.RawBytes()) == "HCRTM" {
			return nil
		}
		return errors.New("unexpected event data contents")
	default:
		return nil
	}
}

func isExpectedDigestValue(digest Digest, t EventType, data EventData, alg AlgorithmId,
	order binary.ByteOrder) (bool, []byte) {
	buf := data.MeasuredBytes()
	var expected []byte

	switch t {
	case EventTypeSeparator:
		if buf == nil {
			buf = make([]byte, 4)
			order.PutUint32(buf, separatorEventErrorValue)
		}
	case EventTypeNoAction:
		expected = zeroDigests[alg]
	}

	switch {
	case buf == nil && expected == nil:
		return true, nil
	case expected == nil:
		expected = hash(buf, alg)
	}

	return bytes.Compare(digest, expected) == 0, expected
}

func checkEventDigests(event *Event, order binary.ByteOrder, report *LogCheckReport) {
	for alg, digest := range event.Digests {
		if ok, expected := isExpectedDigestValue(digest, event.EventType, event.Data, alg, order); !ok {
			report.Entries = append(report.Entries,
				&UnexpectedDigestValueReportEntry{event: event,
					Algorithm: alg,
					Expected:  expected})
		}
	}
}

func checkEvent(event *Event, spec Spec, order binary.ByteOrder, report *LogCheckReport) {
	if !isExpectedEventTypeForIndex(event.EventType, event.PCRIndex, spec) {
		report.Entries = append(report.Entries, &UnexpectedEventTypeReportEntry{event: event})
	}

	if event.dataErr != nil {
		report.Entries = append(report.Entries,
			&InvalidEventDataReportEntry{event: event, err: event.dataErr})
	}

	if err := checkEventData(event.Data, event.EventType); err != nil {
		report.Entries = append(report.Entries, &InvalidEventDataReportEntry{event: event, err: err})
	}

	checkEventDigests(event, order, report)
}

func checkLog(log *Log) (*LogCheckReport, error) {
	report := &LogCheckReport{}

	for {
		event, err := log.NextEvent()
		if err != nil {
			if err == io.EOF {
				return report, nil
			}
			return nil, err
		}

		checkEvent(event, log.Spec, log.byteOrder, report)
	}
}

func CheckLogFromByteReader(reader *bytes.Reader) (*LogCheckReport, error) {
	log, err := NewLogFromByteReader(reader, Options{})
	if err != nil {
		return nil, err
	}
	return checkLog(log)
}

func CheckLogFromFile(file *os.File) (*LogCheckReport, error) {
	log, err := NewLogFromFile(file, Options{})
	if err != nil {
		return nil, err
	}
	return checkLog(log)
}
