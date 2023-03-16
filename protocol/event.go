// Package protocol contains the types, lexer, and parser that implement the
// event server protocol.
package protocol

import (
	"encoding"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"net/netip"
)

const (
	// HTTP represents an event using the HTTP protocol
	HTTP Protocol = 0x0A

	// SMTP represents an event using the SMTP protocol
	SMTP Protocol = 0x11

	// SSH represents an event using the SSH protocol
	SSH Protocol = 0x31

	// TELNET represents an event using the Teletype Network protocol
	TELNET Protocol = 0x23
)

// Protocol is a network protocol type
type Protocol uint16

// String implements the fmt.Stringer interface.
func (p Protocol) String() string {
	s := "UNKNOWN"

	switch p {
	case HTTP:
		s = "HTTP"
	case SMTP:
		s = "SMTP"
	case SSH:
		s = "SSH"
	case TELNET:
		s = "TELNET"
	}

	return s
}

var (
	_ encoding.BinaryMarshaler = (*Event)(nil)
	_ io.ReaderFrom            = (*Event)(nil)
)

// Event is a server-emitted event.
type Event struct {
	NodeID    uint16
	TimeStamp uint32
	Size      uint16
	EventUUID UUID
	Payload   map[string]string
	Protocol  Protocol
	Submitter uint32
	CheckSum  uint32

	PayloadBytes []byte
	IP           netip.Addr
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
//
// This method marshals the entire Event object to its binary equivalent,
// including its CheckSum.
func (e *Event) MarshalBinary() ([]byte, error) {
	return binary.BigEndian.AppendUint32(e.marshalBinary(), e.CheckSum), nil
}

// ReadFrom implements the io.ReaderFrom interface.
func (e *Event) ReadFrom(r io.Reader) (n int64, err error) {
	// NodeID
	if err = binary.Read(r, binary.BigEndian, &e.NodeID); err != nil {
		return 0, fmt.Errorf("reading node ID: %w", err)
	}
	n += 2

	// TimeStamp
	if err = binary.Read(r, binary.BigEndian, &e.TimeStamp); err != nil {
		return n, fmt.Errorf("reading time stamp: %w", err)
	}
	n += 4

	// Size
	if err = binary.Read(r, binary.BigEndian, &e.Size); err != nil {
		return n, fmt.Errorf("reading size: %w", err)
	}
	n += 2

	// UUID
	i, err := e.EventUUID.ReadFrom(r)
	if err != nil {
		return n, fmt.Errorf("reading UUID: %w", err)
	}
	n += i

	// PayloadBytes
	e.PayloadBytes = make([]byte, e.Size)
	j, err := r.Read(e.PayloadBytes)
	switch {
	case err != nil:
		return n, fmt.Errorf("reading payload: %w", err)
	case uint16(j) != e.Size:
		return n, fmt.Errorf("reading payload: read %d of %d bytes", j, e.Size)
	}
	n += int64(j)

	// Parse the raw event payload into key:value pairs.
	parsePayloadRaw(e)

	// Protocol
	if err = binary.Read(r, binary.BigEndian, &e.Protocol); err != nil {
		return n, fmt.Errorf("reading protocol: %w", err)
	}
	n += 2

	// Submitter
	if err = binary.Read(r, binary.BigEndian, &e.Submitter); err != nil {
		return n, fmt.Errorf("reading submitter: %w", err)
	}
	n += 4

	// Derive the IP address from the uint32.
	var addr [4]byte
	binary.BigEndian.PutUint32(addr[:], e.Submitter)
	e.IP = netip.AddrFrom4(addr)

	// CheckSum
	if err = binary.Read(r, binary.BigEndian, &e.CheckSum); err != nil {
		return n, fmt.Errorf("reading checksum: %w", err)
	}
	n += 4

	return n, nil
}

// Valid returns true if the Event's CheckSum value matches the calculated
// CRC-32 checksum of all other Event field values using the IEEE polynomial.
func (e *Event) Valid() bool {
	return crc32.Checksum(e.marshalBinary(), crc32.IEEETable) == e.CheckSum
}

// marshalBinary marshals all fields but the CheckSum to its binary equivalent.
func (e *Event) marshalBinary() []byte {
	b := binary.BigEndian.AppendUint16(make([]byte, 0, 32), e.NodeID)
	b = binary.BigEndian.AppendUint32(b, e.TimeStamp)
	b = binary.BigEndian.AppendUint16(b, e.Size)
	b = append(b, e.EventUUID.marshalBinary()...)
	b = append(b, e.PayloadBytes...)
	b = binary.BigEndian.AppendUint16(b, uint16(e.Protocol))
	b = binary.BigEndian.AppendUint32(b, e.Submitter)

	return b
}
