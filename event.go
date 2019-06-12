package tcglog

import (
	"encoding/hex"
	"fmt"
)

type PCRIndex uint32
type EventType uint32
type AlgorithmId uint16
type Digest []byte
type DigestMap map[AlgorithmId]Digest

func (e EventType) Label() string {
	switch e {
	case EventTypePrebootCert:
		return "EV_PREBOOT_CERT"
	case EventTypePostCode:
		return "EV_POST_CODE"
	case EventTypeNoAction:
		return "EV_NO_ACTION"
	case EventTypeSeparator:
		return "EV_SEPARATOR"
	case EventTypeAction:
		return "EV_ACTION"
	case EventTypeEventTag:
		return "EV_EVENT_TAG"
	case EventTypeSCRTMContents:
		return "EV_S_CRTM_CONTENTS"
	case EventTypeSCRTMVersion:
		return "EV_S_CRTM_VERSION"
	case EventTypeCPUMicrocode:
		return "EV_CPU_MICROCODE"
	case EventTypePlatformConfigFlags:
		return "EV_PLATFORM_CONFIG_FLAGS"
	case EventTypeTableOfDevices:
		return "EV_TABLE_OF_DEVICES"
	case EventTypeCompactHash:
		return "EV_COMPACT_HASH"
	case EventTypeIPL:
		return "EV_IPL"
	case EventTypeIPLPartitionData:
		return "EV_IPL_PARTITION_DATA"
	case EventTypeNonhostCode:
		return "EV_NONHOST_CODE"
	case EventTypeNonhostConfig:
		return "EV_NONHOST_CONFIG"
	case EventTypeNonhostInfo:
		return "EV_NONHOST_INFO"
	case EventTypeOmitBootDeviceEvents:
		return "EV_OMIT_BOOT_DEVICE_EVENTS"
	case EventTypeEFIVariableDriverConfig:
		return "EV_EFI_VARIABLE_DRIVER_CONFIG"
	case EventTypeEFIVariableBoot:
		return "EV_EFI_VARIABLE_BOOT"
	case EventTypeEFIBootServicesApplication:
		return "EV_EFI_BOOT_SERVICES_APPLICATION"
	case EventTypeEFIBootServicesDriver:
		return "EV_EFI_BOOT_SERVICES_DRIVER"
	case EventTypeEFIRuntimeServicesDriver:
		return "EV_EFI_RUNTIME_SERVICES_DRIVER"
	case EventTypeEFIGPTEvent:
		return "EF_EFI_GPT_EVENT"
	case EventTypeEFIAction:
		return "EV_EFI_ACTION"
	case EventTypeEFIPlatformFirmwareBlob:
		return "EV_EFI_PLATFORM_FIRMWARE_BLOB"
	case EventTypeEFIHandoffTables:
		return "EV_EFI_HANDOFF_TABLES"
	case EventTypeEFIHCRTMEvent:
		return "EV_EFI_HCRTM_EVENT"
	case EventTypeEFIVariableAuthority:
		return "EV_EFI_VARIABLE_AUTHORITY"
	default:
		return fmt.Sprintf("%08x", uint32(e))
	}
}

func (e EventType) Format(s fmt.State, f rune) {
	switch f {
	case 's':
		fmt.Fprintf(s, "%s", e.Label())
	// case 'x':
	//     TODO
	// case 'X':
	//     TODO
	default:
		fmt.Fprintf(s, "%%!%c(tcglog.EventType=%08x)", f, uint32(e))
	}
}

func (a AlgorithmId) String() string {
	switch a {
	case AlgorithmSha1:
		return "SHA-1"
	case AlgorithmSha256:
		return "SHA-256"
	case AlgorithmSha384:
		return "SHA-384"
	case AlgorithmSha512:
		return "SHA-512"
	default:
		return fmt.Sprintf("%04x", uint16(a))
	}
}

func (a AlgorithmId) Format(s fmt.State, f rune) {
	switch f {
	case 's':
		fmt.Fprintf(s, "%s", a.String())
	default:
		fmt.Fprintf(s, "%%!%c(tcglog.AlgorithmId=%04x)", f, uint16(a))
	}
}

func (d Digest) Format(s fmt.State, f rune) {
	switch f {
	case 's':
		fmt.Fprintf(s, "%s", hex.EncodeToString([]byte(d)))
	default:
		fmt.Fprintf(s, "%%!%c(tcglog.Digest=%s)", f, hex.EncodeToString([]byte(d)))
	}
}

type Event struct {
	PCRIndex  PCRIndex
	EventType EventType
	Digests   DigestMap
	Data      EventData
}
