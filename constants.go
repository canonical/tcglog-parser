// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

import (
	"math"
)

const (
	EventTypePrebootCert EventType = 0x00000000 // EV_PREBOOT_CERT
	EventTypePostCode    EventType = 0x00000001 // EV_POST_CODE
	// EventTypeUnused = 0x00000002
	EventTypeNoAction             EventType = 0x00000003 // EV_NO_ACTION
	EventTypeSeparator            EventType = 0x00000004 // EV_SEPARATOR
	EventTypeAction               EventType = 0x00000005 // EV_ACTION
	EventTypeEventTag             EventType = 0x00000006 // EV_EVENT_TAG
	EventTypeSCRTMContents        EventType = 0x00000007 // EV_S_CRTM_CONTENTS
	EventTypeSCRTMVersion         EventType = 0x00000008 // EV_S_CRTM_VERSION
	EventTypeCPUMicrocode         EventType = 0x00000009 // EV_CPU_MICROCODE
	EventTypePlatformConfigFlags  EventType = 0x0000000a // EV_PLATFORM_CONFIG_FLAGS
	EventTypeTableOfDevices       EventType = 0x0000000b // EV_TABLE_OF_DEVICES
	EventTypeCompactHash          EventType = 0x0000000c // EV_COMPACT_HASH
	EventTypeIPL                  EventType = 0x0000000d // EV_IPL
	EventTypeIPLPartitionData     EventType = 0x0000000e // EV_IPL_PARTITION_DATA
	EventTypeNonhostCode          EventType = 0x0000000f // EV_NONHOST_CODE
	EventTypeNonhostConfig        EventType = 0x00000010 // EV_NONHOST_CONFIG
	EventTypeNonhostInfo          EventType = 0x00000011 // EV_NONHOST_INFO
	EventTypeOmitBootDeviceEvents EventType = 0x00000012 // EV_OMIT_BOOT_DEVICE_EVENTS

	EventTypeEFIEventBase               EventType = 0x80000000 // EV_EFI_EVENT_BASE
	EventTypeEFIVariableDriverConfig    EventType = 0x80000001 // EV_EFI_VARIABLE_DRIVER_CONFIG
	EventTypeEFIVariableBoot            EventType = 0x80000002 // EV_EFI_VARIABLE_BOOT
	EventTypeEFIBootServicesApplication EventType = 0x80000003 // EV_EFI_BOOT_SERVICES_APPLICATION
	EventTypeEFIBootServicesDriver      EventType = 0x80000004 // EV_EFI_BOOT_SERVICES_DRIVER
	EventTypeEFIRuntimeServicesDriver   EventType = 0x80000005 // EV_EFI_RUNTIME_SERVICES_DRIVER
	EventTypeEFIGPTEvent                EventType = 0x80000006 // EV_EFI_GPT_EVENT
	EventTypeEFIAction                  EventType = 0x80000007 // EV_EFI_ACTION
	EventTypeEFIPlatformFirmwareBlob    EventType = 0x80000008 // EV_EFI_PLATFORM_FIRMWARE_BLOB
	EventTypeEFIHandoffTables           EventType = 0x80000009 // EF_EFI_HANDOFF_TABLES
	EventTypeEFIHCRTMEvent              EventType = 0x80000010 // EF_EFI_HCRTM_EVENT
	EventTypeEFIVariableAuthority       EventType = 0x800000e0 // EV_EFI_VARIABLE_AUTHORITY
)

const (
	AlgorithmSha1   AlgorithmId = 0x0004 // TPM_ALG_SHA1
	AlgorithmSha256 AlgorithmId = 0x000b // TPM_ALG_SHA256
	AlgorithmSha384 AlgorithmId = 0x000c // TPM_ALG_SHA384
	AlgorithmSha512 AlgorithmId = 0x000d // TPM_ALG_SHA512
)

const (
	// SpecUnknown indicates that the specification to which the log conforms is unknown because it doesn't
	// start with a spec ID event.
	SpecUnknown Spec = iota

	// SpecPCClient indicates that the log conforms to "TCG PC Client Specific Implementation Specification
	// for Conventional BIOS".
	// See https://www.trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
	SpecPCClient

	// SpecEFI_1_2 indicates that the log conforms to "TCG EFI Platform Specification For TPM Family 1.1 or
	// 1.2".
	// See https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
	SpecEFI_1_2

	// SpecEFI_2 indicates that the log conforms to "TCG PC Client Platform Firmware Profile Specification"
	// See https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
	SpecEFI_2
)

const (
	SeparatorEventNormalValue    uint32 = 0
	SeparatorEventErrorValue     uint32 = 1
	SeparatorEventAltNormalValue uint32 = math.MaxUint32
)

var (
	EFICallingEFIApplicationEvent       = StringEventData("Calling EFI Application from Boot Option")
	EFIReturningFromEFIApplicationEvent = StringEventData("Returning from EFI Application from Boot Option")
	EFIExitBootServicesInvocationEvent  = StringEventData("Exit Boot Services Invocation")
	EFIExitBootServicesFailedEvent      = StringEventData("Exit Boot Services Returned with Failure")
	EFIExitBootServicesSucceededEvent   = StringEventData("Exit Boot Services Returned with Success")
	FirmwareDebuggerEvent               = StringEventData("UEFI Debug Mode")
)
