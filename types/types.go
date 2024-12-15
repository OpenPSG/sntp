// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package types

import "encoding/binary"

// LeapIndicator signifies whether a leap second will be added or subtracted at midnight.
type LeapIndicator uint8

const (
	// No leap second adjustment is required.
	LeapIndicatorNoAdjustment LeapIndicator = 0
	// Last minute of the day has 61 seconds.
	LeapIndicatorAddSecond LeapIndicator = 1
	// Last minute of the day has 59 seconds.
	LeapIndicatorSubtractSecond LeapIndicator = 2
	// Leap second state is unknown.
	LeapIndicatorAlarmCondition LeapIndicator = 3
)

// Version represents the version number of the SNTP packet.
type Version uint8

const (
	// Version 1.
	Version1 Version = 1
	// Version 2.
	Version2 Version = 2
	// Version 3.
	Version3 Version = 3
	// Version 4 (current).
	Version4 Version = 4
)

// Mode defines the operation mode of the SNTP packet.
type Mode uint8

const (
	// Reserved mode.
	ModeReserved Mode = 0
	// Symmetric active.
	ModeSymmetricActive Mode = 1
	// Symmetric passive.
	ModeSymmetricPassive Mode = 2
	// Client mode.
	ModeClient Mode = 3
	// Server mode.
	ModeServer Mode = 4
	// Broadcast mode.
	ModeBroadcast Mode = 5
	// NTP control message.
	ModeControlMessage Mode = 6
	// Private use.
	ModePrivate Mode = 7
)

// StratumLevel defines the stratum level of the SNTP server.
type StratumLevel uint8

const (
	// Unspecified or invalid stratum level.
	StratumUnspecified StratumLevel = 0
	// Primary reference (e.g., GPS).
	StratumPrimary StratumLevel = 1
	// Secondary reference (via NTP, using another server).
	StratumSecondary StratumLevel = 2
	// Tertiary and beyond.
	StratumTertiary StratumLevel = 3
	// Reserved for future use or custom definitions.
	StratumReserved StratumLevel = 255
)

// PollInterval represents encoded poll intervals in logarithmic scale.
type PollInterval int8

const (
	// Minimum poll interval (16 seconds).
	PollIntervalMinimum PollInterval = 4
	// Default poll interval (64 seconds).
	PollIntervalDefault PollInterval = 6
	// Maximum poll interval (1024 seconds).
	PollIntervalMaximum PollInterval = 10
)

// PrecisionLevel represents common precision levels of the local clock in logarithmic scale.
type PrecisionLevel int8

const (
	// Clock precision is 1 second.
	PrecisionOneSecond PrecisionLevel = 0
	// Clock precision is 1 millisecond.
	PrecisionOneMillisecond PrecisionLevel = -10
	// Clock precision is 1 microsecond.
	PrecisionOneMicrosecond PrecisionLevel = -20
	// Clock precision is 1 nanosecond.
	PrecisionOneNanosecond PrecisionLevel = -30
)

// ExternalReferenceSourceCode represents the external reference source code.
type ExternalReferenceSourceCode string

const (
	// Uncalibrated local clock.
	ExternalReferenceSourceLocal ExternalReferenceSourceCode = "LOCL"
	// Calibrated Cesium clock.
	ExternalReferenceSourceCesium ExternalReferenceSourceCode = "CESM"
	// Calibrated Rubidium clock.
	ExternalReferenceSourceRubidium ExternalReferenceSourceCode = "RBDM"
	// Calibrated quartz clock or other pulse-per-second source.
	ExternalReferenceSourcePulsePerSecond ExternalReferenceSourceCode = "PPS"
	// Inter-Range Instrumentation Group.
	ExternalReferenceSourceIRIG ExternalReferenceSourceCode = "IRIG"
	// NIST telephone modem service.
	ExternalReferenceSourceACTS ExternalReferenceSourceCode = "ACTS"
	// USNO telephone modem service.
	ExternalReferenceSourceUSNO ExternalReferenceSourceCode = "USNO"
	// PTB (Germany) telephone modem service.
	ExternalReferenceSourcePTB ExternalReferenceSourceCode = "PTB"
	// Allouis (France) Radio 164 kHz.
	ExternalReferenceSourceTDF ExternalReferenceSourceCode = "TDF"
	// Mainflingen (Germany) Radio 77.5 kHz.
	ExternalReferenceSourceDCF ExternalReferenceSourceCode = "DCF"
	// Rugby (UK) Radio 60 kHz.
	ExternalReferenceSourceMSF ExternalReferenceSourceCode = "MSF"
	// Ft. Collins (US) Radio 2.5, 5, 10, 15, 20 MHz.
	ExternalReferenceSourceWWV ExternalReferenceSourceCode = "WWV"
	// Boulder (US) Radio 60 kHz.
	ExternalReferenceSourceWWVB ExternalReferenceSourceCode = "WWVB"
	// Kauai Hawaii (US) Radio 2.5, 5, 10, 15 MHz.
	ExternalReferenceSourceWWVH ExternalReferenceSourceCode = "WWVH"
	// Ottawa (Canada) Radio 3330, 7335, 14670 kHz.
	ExternalReferenceSourceCHU ExternalReferenceSourceCode = "CHU"
	// LORAN-C radionavigation system.
	ExternalReferenceSourceLORAN ExternalReferenceSourceCode = "LORC"
	// OMEGA radionavigation system.
	ExternalReferenceSourceOMEGA ExternalReferenceSourceCode = "OMEG"
	// Global Positioning Service.
	ExternalReferenceSourceGPS ExternalReferenceSourceCode = "GPS"
)

// KissOfDeathCode is a kiss code that can be sent by an NTP server to a client to
// indicate that the client should stop sending requests.
type KissOfDeathCode string

const (
	// The association belongs to an anycast server.
	KissOfDeathCodeAssocitation KissOfDeathCode = "ACST"
	// Server authentication failed.
	KissOfDeathCodeAuthentication KissOfDeathCode = "AUTH"
	// Autokey sequence failed.
	KissOfDeathCodeAutokey KissOfDeathCode = "AUTO"
	// The association belongs to a broadcast server.
	KissOfDeathCodeBroadcast KissOfDeathCode = "BCST"
	// Cryptographic authentication or identification failed.
	KissOfDeathCodeCryptographic KissOfDeathCode = "CRYP"
	// Access denied by remote server.
	KissOfDeathCodeDeny KissOfDeathCode = "DENY"
	// Lost peer in symmetric mode.
	KissOfDeathCodeLostPeer KissOfDeathCode = "DROP"
	// Access denied due to local policy.
	KissOfDeathCodeLocalPolicy KissOfDeathCode = "RSTR"
	// The association has not yet synchronized for the first time.
	KissOfDeathCodeNotSynchronized KissOfDeathCode = "INIT"
	// The association belongs to a manycast server.
	KissOfDeathCodeManycast KissOfDeathCode = "MCST"
	// No key found. Either the key was never installed or is not trusted.
	KissOfDeathCodeNoKeyFound KissOfDeathCode = "NKEY"
	// Rate exceeded. The server has temporarily denied access because the client exceeded the rate threshold.
	KissOfDeathCodeRateExceeded KissOfDeathCode = "RATE"
	// Somebody is tinkering with the association from a remote host running ntpdc.
	KissOfDeathCodeRemote KissOfDeathCode = "RMOT"
	// A step change in system time has occurred, but the association has not yet resynchronized.
	KissOfDeathCodeStepNotSynchronized KissOfDeathCode = "STEP"
)

// Packet represents an SNTP packet.
type Packet struct {
	// Includes Leap Indicator, Version Number, and Mode.
	LiVnMode uint8
	// Indicates the level of the local clock.
	Stratum StratumLevel
	// Maximum interval between successive messages.
	Poll PollInterval
	// Precision of the local clock.
	Precision PrecisionLevel
	// Total round trip delay to the primary reference source.
	RootDelay uint32
	// Maximum error relative to the primary reference source.
	RootDispersion uint32
	// Identifier of the particular server or reference clock.
	ReferenceID uint32
	// Time when the system clock was last set or corrected.
	RefTimestamp uint64
	// Time at the client when the request departed.
	OrigTimestamp uint64
	// Time at the server when the request arrived.
	RecvTimestamp uint64
	// Time at the server when the response left.
	XmitTimestamp uint64
}

// SetLeapIndicator sets the leap indicator of the packet.
func (p *Packet) SetLeapIndicator(leap LeapIndicator) {
	p.LiVnMode = (p.LiVnMode & 0x3F) | (uint8(leap) << 6)
}

// GetLeapIndicator gets the leap indicator of the packet.
func (p *Packet) GetLeapIndicator() LeapIndicator {
	return LeapIndicator((p.LiVnMode >> 6) & 0x03)
}

// SetVersion sets the version number of the packet.
func (p *Packet) SetVersion(version Version) {
	p.LiVnMode = (p.LiVnMode & 0xC7) | (uint8(version&0x07) << 3)
}

// GetVersion gets the version number of the packet.
func (p *Packet) GetVersion() Version {
	return Version((p.LiVnMode >> 3) & 0x07)
}

// SetMode sets the mode of the packet.
func (p *Packet) SetMode(mode Mode) {
	p.LiVnMode = (p.LiVnMode & 0xF8) | uint8(mode)
}

// GetMode gets the mode of the packet.
func (p *Packet) GetMode() Mode {
	return Mode(p.LiVnMode & 0x07)
}

// SetExternalReferenceSource sets the external clock reference source for
// stratum 1 servers.
func (p *Packet) SetExternalReferenceSource(code ExternalReferenceSourceCode) {
	b := make([]byte, 4)
	copy(b, []byte(code))
	p.ReferenceID = binary.BigEndian.Uint32(b)
}

// SetKissOfDeath sets the kiss of death code for the packet.
func (p *Packet) SetKissOfDeath(code KissOfDeathCode) {
	b := make([]byte, 4)
	copy(b, []byte(code))
	p.ReferenceID = binary.BigEndian.Uint32(b)
}
