// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

var (
	DecodeEventDataEFIGPT                   = decodeEventDataEFIGPT
	DecodeEventDataEFIHCRTMEvent            = decodeEventDataEFIHCRTMEvent
	DecodeEventDataEFIImageLoad             = decodeEventDataEFIImageLoad
	DecodeEventDataEFIVariable              = decodeEventDataEFIVariable
	DecodeEventDataAction                   = decodeEventDataAction
	DecodeEventDataNoAction                 = decodeEventDataNoAction
	DecodeEventDataOmitBootDeviceEvents     = decodeEventDataOmitBootDeviceEvents
	DecodeEventDataSCRTMContents            = decodeEventDataSCRTMContents
	DecodeEventDataSCRTMVersion             = decodeEventDataSCRTMVersion
	DecodeEventDataSeparator                = decodeEventDataSeparator
	DecodeEventDataSystemdEFIStub           = decodeEventDataSystemdEFIStub
	DecodeEventDataCompactHash              = decodeEventDataCompactHash
	DecodeEventDataPostCode                 = decodeEventDataPostCode
	DecodeEventDataPostCode2                = decodeEventDataPostCode2
	DecodeEventDataEFIPlatformFirmwareBlob  = decodeEventDataEFIPlatformFirmwareBlob
	DecodeEventDataEFIPlatformFirmwareBlob2 = decodeEventDataEFIPlatformFirmwareBlob2
	DecodeEventDataEFIHandoffTablePointers  = decodeEventDataEFIHandoffTablePointers
	FormatString                            = formatString
)
