package protocol

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
)

var _ io.ReaderFrom = (*UUID)(nil)

// UUID is a 128-bit universally unique identifier using the format described
// at: https://en.wikipedia.org/wiki/Universally_unique_identifier#Format
//
// I confirmed this is the expected format by taking a peek at the type in the
// emitter binary.
type UUID struct {
	TimeLow          uint32
	TimeMid          uint16
	TimeHiAndVersion uint16
	ClockSeqHiAndRes byte
	ClockSeqLow      byte
	Node             [6]byte
}

// ReadFrom implements the io.ReaderFrom interface.
func (u *UUID) ReadFrom(r io.Reader) (n int64, err error) {
	// TimeLow
	if err = binary.Read(r, binary.BigEndian, &u.TimeLow); err != nil {
		return n, fmt.Errorf("reading time low: %w", err)
	}
	n += 4

	// TimeMid
	if err = binary.Read(r, binary.BigEndian, &u.TimeMid); err != nil {
		return n, fmt.Errorf("reading time mid: %w", err)
	}
	n += 2

	// TimeHiAndVersion
	if err = binary.Read(r, binary.BigEndian, &u.TimeHiAndVersion); err != nil {
		return n, fmt.Errorf("reading time hi and version: %w", err)
	}
	n += 2

	// ClockSeqHiAndRes
	if err = binary.Read(r, binary.BigEndian, &u.ClockSeqHiAndRes); err != nil {
		return n, fmt.Errorf("reading clock seq hi and res: %w", err)
	}
	n++

	// ClockSeqLow
	if err = binary.Read(r, binary.BigEndian, &u.ClockSeqLow); err != nil {
		return n, fmt.Errorf("reading clock seq low: %w", err)
	}
	n++

	// Node
	i, err := r.Read(u.Node[:])
	switch {
	case err != nil:
		return n, fmt.Errorf("reading node: %w", err)
	case i != 6:
		return n, fmt.Errorf("reading node: read %d of 6 bytes", i)
	}
	n += int64(i)

	return n, nil
}

// String implements the fmt.Stringer interface.
func (u *UUID) String() string {
	dst := make([]byte, 36)
	src := u.marshalBinary()

	// TimeLow
	hex.Encode(dst, src[:4])
	dst[8] = '-'

	// TimeMid
	hex.Encode(dst[9:13], src[4:6])
	dst[13] = '-'

	// TimeHiAndVersion
	hex.Encode(dst[14:18], src[6:8])
	dst[18] = '-'

	// ClockSeqHiAndRes:ClockSeqLow
	hex.Encode(dst[19:23], src[8:10])
	dst[23] = '-'

	// Node
	hex.Encode(dst[24:], src[10:])

	return string(dst)
}

func (u *UUID) marshalBinary() []byte {
	b := binary.BigEndian.AppendUint32([]byte{}, u.TimeLow)
	b = binary.BigEndian.AppendUint16(b, u.TimeMid)
	b = binary.BigEndian.AppendUint16(b, u.TimeHiAndVersion)
	b = append(b, u.ClockSeqHiAndRes, u.ClockSeqLow)
	b = append(b, u.Node[:]...)

	return b
}
