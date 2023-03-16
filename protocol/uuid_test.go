package protocol

import (
	"bytes"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

var uuid = &UUID{
	TimeLow:          0x35633061,
	TimeMid:          0x6663,
	TimeHiAndVersion: 0x3630,
	ClockSeqHiAndRes: 0x2d,
	ClockSeqLow:      0x34,
	Node: [6]uint8{
		0x66,
		0x35,
		0x38,
		0x2d,
		0x31,
		0x31,
	},
}

func TestUUID_ReadFrom(t *testing.T) {
	Convey("Given a valid UUID", t, func() {
		Convey("When reading its bytes into a new UUID", func() {
			buf := bytes.NewBuffer(uuid.marshalBinary())
			u := new(UUID)

			Convey("It should result in a duplicate UUID", func() {
				n, err := u.ReadFrom(buf)
				So(err, ShouldBeNil)
				So(n, ShouldEqual, 16)
				So(u, ShouldResemble, uuid)
			})

			Convey("It should return an error on a short read of the Node", func() {
				buf.Truncate(buf.Len() - 2)
				_, err := u.ReadFrom(buf)
				So(err, ShouldBeError)
				So(err.Error(), ShouldEqual, "reading node: read 4 of 6 bytes")
			})

			Convey("It should return an error on reaching EOF when reading the Node", func() {
				buf.Truncate(buf.Len() - 6)
				_, err := u.ReadFrom(buf)
				So(err, ShouldBeError)
				So(err.Error(), ShouldEqual, "reading node: EOF")
			})

			Convey("It should return an error on a short read of the ClockSeqLow", func() {
				buf.Truncate(buf.Len() - 7)
				_, err := u.ReadFrom(buf)
				So(err, ShouldBeError)
				So(err.Error(), ShouldEqual, "reading clock seq low: EOF")
			})

			Convey("It should return an error on a short read of the ClockSeqHiAndRes", func() {
				buf.Truncate(buf.Len() - 8)
				_, err := u.ReadFrom(buf)
				So(err, ShouldBeError)
				So(err.Error(), ShouldEqual, "reading clock seq hi and res: EOF")
			})

			Convey("It should return an error on a short read of the TimeHiAndVersion", func() {
				buf.Truncate(buf.Len() - 9)
				_, err := u.ReadFrom(buf)
				So(err, ShouldBeError)
				So(err.Error(), ShouldEqual, "reading time hi and version: unexpected EOF")
			})

			Convey("It should return an error on a short read of the TimeMid", func() {
				buf.Truncate(buf.Len() - 11)
				_, err := u.ReadFrom(buf)
				So(err, ShouldBeError)
				So(err.Error(), ShouldEqual, "reading time mid: unexpected EOF")
			})

			Convey("It should return an error on a short read of the TimeLow", func() {
				buf.Truncate(buf.Len() - 14)
				_, err := u.ReadFrom(buf)
				So(err, ShouldBeError)
				So(err.Error(), ShouldEqual, "reading time low: unexpected EOF")
			})
		})
	})
}

func TestUUID_String(t *testing.T) {
	Convey("Given a valid UUID", t, func() {
		Convey("When converting its value to a string", func() {
			Convey("It should return the expected output", func() {
				expected := "35633061-6663-3630-2d34-6635382d3131"
				So(uuid.String(), ShouldEqual, expected)
			})
		})
	})
}
