package tcglog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"unsafe"
)

type LogCheckOptions struct {
	EnableGrub           bool
	EfiVariableBootQuirk bool
}

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

type LogCheckReportEntry interface {
	String() string
	Event() *Event
}

type LogCheckReport struct {
	Entries []LogCheckReportEntry
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 3.3.2.2 2 Error Conditions" , section 8.2.3 "Measuring Boot Events")
// https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf:
//  (section 2.3.2 "Error Conditions", section 2.3.4 "PCR Usage", section 7.2
//   "Procedure for Pre-OS to OS-Present Transition")
var (
	separatorEventNormalValues        = [...]uint32{0, math.MaxUint32}
)

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

func checkEventData(event *Event, order binary.ByteOrder) error {
	switch event.EventType {
	case EventTypeSeparator:
		if isSeparatorEventError(event, order) {
			return nil
		}
		s := len(event.Data.Bytes())
		if s != 4 {
			return fmt.Errorf("unexpected event data size of %d", s)
		}
		for _, v := range separatorEventNormalValues {
			if v == *(*uint32)(unsafe.Pointer(&event.Data.Bytes()[0])) {
				return nil
			}
		}
		return errors.New("unexpected event data contents")
	case EventTypeCompactHash:
		s := len(event.Data.Bytes())
		if s == 4 {
			return nil
		}
		return fmt.Errorf("unexpected event data size of %d", s)
	case EventTypeOmitBootDeviceEvents:
		if string(event.Data.Bytes()) == "BOOT ATTEMPTS OMITTED" {
			return nil
		}
		return errors.New("unexpected event data contents - expected \"BOOT ATTEMPTS OMITTED\"")
	case EventTypeEFIHCRTMEvent:
		if string(event.Data.Bytes()) == "HCRTM" {
			return nil
		}
		return errors.New("unexpected event data contents - expected \"HCRTM\"")
	default:
		return nil
	}
}

func checkEvent(event *Event, dataErr error, spec Spec, order binary.ByteOrder, options *LogCheckOptions,
	report *LogCheckReport) {
	if !isExpectedEventTypeForIndex(event.EventType, event.PCRIndex, spec) {
		report.Entries = append(report.Entries, &UnexpectedEventTypeReportEntry{event: event})
	}

	if dataErr != nil {
		report.Entries = append(report.Entries,
			&InvalidEventDataReportEntry{event: event, err: dataErr})
	}

	if err := checkEventData(event, order); err != nil {
		report.Entries = append(report.Entries, &InvalidEventDataReportEntry{event: event, err: err})
	}
}

func checkLog(log *Log, options LogCheckOptions) (*LogCheckReport, error) {
	report := &LogCheckReport{}

	for {
		event, _, err := log.nextEventInternal()
		if event == nil {
			if err == io.EOF {
				return report, nil
			}
			return nil, err
		}

		checkEvent(event, err, log.Spec, log.byteOrder, &options, report)
	}
}

func CheckLogFromByteReader(reader *bytes.Reader, options LogCheckOptions) (*LogCheckReport, error) {
	log, err := NewLogFromByteReader(reader, LogOptions{EnableGrub: options.EnableGrub})
	if err != nil {
		return nil, err
	}
	return checkLog(log, options)
}

func CheckLogFromFile(file *os.File, options LogCheckOptions) (*LogCheckReport, error) {
	log, err := NewLogFromFile(file, LogOptions{EnableGrub: options.EnableGrub})
	if err != nil {
		return nil, err
	}
	return checkLog(log, options)
}
