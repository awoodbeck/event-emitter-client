package protocol

import (
	"bytes"
	"net/netip"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

// payload read via Wireshark from the event server
var payload = "\x00\x04\x5f\x87\x91\x00\x00\x92\x35\x61\x62\x65\x38\x35\x32\x32" +
	"\x2d\x34\x66\x36\x30\x2d\x31\x31\x75\x73\x65\x72\x2d\x61\x67\x65" +
	"\x6e\x74\x3a\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x35\x2e\x30\x20\x28" +
	"\x69\x50\x68\x6f\x6e\x65\x3b\x20\x43\x50\x55\x20\x69\x50\x68\x6f" +
	"\x6e\x65\x20\x4f\x53\x20\x31\x30\x5f\x33\x5f\x33\x20\x6c\x69\x6b" +
	"\x65\x20\x4d\x61\x63\x20\x4f\x53\x20\x58\x29\x20\x41\x70\x70\x6c" +
	"\x65\x57\x65\x62\x4b\x69\x74\x2f\x36\x30\x33\x2e\x33\x2e\x38\x20" +
	"\x28\x4b\x48\x54\x4d\x4c\x2c\x20\x6c\x69\x6b\x65\x20\x47\x65\x63" +
	"\x6b\x6f\x29\x20\x56\x65\x72\x73\x69\x6f\x6e\x2f\x39\x2e\x30\x20" +
	"\x4d\x6f\x62\x69\x6c\x65\x2f\x31\x33\x42\x31\x34\x33\x20\x53\x61" +
	"\x66\x61\x72\x69\x2f\x36\x30\x31\x2e\x31\x00\x0a\xe4\xf7\xb9\xba" +
	"\x75\x0f\x47\x97"

func TestEvent_MarshalBinary(t *testing.T) {
	Convey("Given a populated Event", t, func() {
		e := &Event{
			NodeID:    0x4,
			TimeStamp: 0x5f80f980,
			Size:      0x27,
			EventUUID: UUID{
				TimeLow:          0x66643236,
				TimeMid:          0x3039,
				TimeHiAndVersion: 0x3063,
				ClockSeqHiAndRes: 0x2d,
				ClockSeqLow:      0x35,
				Node:             [6]uint8{0x30, 0x64, 0x63, 0x2d, 0x31, 0x31},
			},
			Payload: map[string]string{
				"password": "Stingercoconut",
				"username": "joseph",
			},
			Protocol:  0x31,
			Submitter: 0x2f78664c,
			CheckSum:  0xf671b203,
			PayloadBytes: []uint8{
				0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x3a, 0x6a, 0x6f, 0x73, 0x65, 0x70,
				0x68, 0x2c, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x3a, 0x53, 0x74, 0x69,
				0x6e, 0x67, 0x65, 0x72, 0x63, 0x6f, 0x63, 0x6f, 0x6e, 0x75, 0x74,
			},
			IP: netip.MustParseAddr("47.120.102.76"),
		}
		Convey("When calling its MarshalBinary method", func() {
			Convey("It should successfully marshal itself to binary", func() {
				b, err := e.MarshalBinary()
				So(err, ShouldBeNil)
				So(b, ShouldHaveLength, 73)

				// The real test: can we reconstitute the Event from its binary
				// representation?
				e2 := new(Event)
				n, err := e2.ReadFrom(bytes.NewBuffer(b))
				So(err, ShouldBeNil)
				So(n, ShouldEqual, 73)
				So(e2, ShouldResemble, e)
			})
		})
	})
}

func TestEvent_ReadFrom(t *testing.T) {
	Convey("Given a payload of an event emitted by the server", t, func() {
		buf := bytes.NewBufferString(payload)

		Convey("When passing it to an Event's ReadFrom method", func() {
			Convey("It should succeed when reading the entire payload", func() {
				n, err := (new(Event)).ReadFrom(buf)
				So(err, ShouldBeNil)
				So(n, ShouldEqual, len(payload))
			})

			Convey("It should return an error on short read of the CheckSum", func() {
				buf.Truncate(buf.Len() - 2)
				_, err := (new(Event)).ReadFrom(buf)
				So(err, ShouldBeError)
				So(err.Error(), ShouldEqual, "reading checksum: unexpected EOF")
			})

			Convey("It should return an error on short read of the Submitter", func() {
				buf.Truncate(buf.Len() - 5)
				_, err := (new(Event)).ReadFrom(buf)
				So(err, ShouldBeError)
				So(err.Error(), ShouldEqual, "reading submitter: unexpected EOF")
			})

			Convey("It should return an error on short read of the Protocol", func() {
				buf.Truncate(buf.Len() - 9)
				_, err := (new(Event)).ReadFrom(buf)
				So(err, ShouldBeError)
				So(err.Error(), ShouldEqual, "reading protocol: unexpected EOF")
			})

			Convey("It should return an error on short read of the Payload", func() {
				buf.Truncate(buf.Len() - 20)
				_, err := (new(Event)).ReadFrom(buf)
				So(err, ShouldBeError)
				So(err.Error(), ShouldEqual, "reading payload: read 136 of 146 bytes")
			})

			Convey("It should return an error when encountering an EOF at reading the Payload", func() {
				buf.Truncate(buf.Len() - 156)
				_, err := (new(Event)).ReadFrom(buf)
				So(err, ShouldBeError)
				So(err.Error(), ShouldEqual, "reading payload: EOF")
			})

			Convey("It should return an error on short read of the UUID", func() {
				buf.Truncate(buf.Len() - 160)
				_, err := (new(Event)).ReadFrom(buf)
				So(err, ShouldBeError)
				So(err.Error(), ShouldEqual, "reading UUID: reading node: read 2 of 6 bytes")
			})

			Convey("It should return an error on short read of the Size", func() {
				buf.Truncate(buf.Len() - 173)
				_, err := (new(Event)).ReadFrom(buf)
				So(err, ShouldBeError)
				So(err.Error(), ShouldEqual, "reading size: unexpected EOF")
			})

			Convey("It should return an error on short read of the TimeStamp", func() {
				buf.Truncate(buf.Len() - 175)
				_, err := (new(Event)).ReadFrom(buf)
				So(err, ShouldBeError)
				So(err.Error(), ShouldEqual, "reading time stamp: unexpected EOF")
			})

			Convey("It should return an error on short read of the NodeID", func() {
				buf.Truncate(buf.Len() - 179)
				_, err := (new(Event)).ReadFrom(buf)
				So(err, ShouldBeError)
				So(err.Error(), ShouldEqual, "reading node ID: unexpected EOF")
			})
		})
	})
}

func TestEvent_Valid(t *testing.T) {
	Convey("Given a payload of an event emitted by the server", t, func() {
		buf := bytes.NewBufferString(payload)

		Convey("When populating an Event and calling its Valid method", func() {
			Convey("It should return true", func() {
				e := new(Event)
				n, err := e.ReadFrom(buf)
				So(err, ShouldBeNil)
				So(n, ShouldEqual, len(payload))
				So(e.Valid(), ShouldBeTrue)
			})

			Convey("It should return false on an invalid payload", func() {
				e := new(Event)
				n, err := e.ReadFrom(buf)
				So(err, ShouldBeNil)
				So(n, ShouldEqual, len(payload))

				// tweak the checksum so it no longer verifies the payload
				e.CheckSum++
				So(e.Valid(), ShouldBeFalse)
			})
		})
	})
}

func TestProtocol_String(t *testing.T) {
	Convey("Given a Protocol constant", t, func() {
		Convey("When calling its String method", func() {
			Convey("It should return the expected string for HTTP", func() {
				So(HTTP.String(), ShouldEqual, "HTTP")
			})

			Convey("It should return the expected string for SMTP", func() {
				So(SMTP.String(), ShouldEqual, "SMTP")
			})

			Convey("It should return the expected string for SSH", func() {
				So(SSH.String(), ShouldEqual, "SSH")
			})

			Convey("It should return the expected string for TELNET", func() {
				So(TELNET.String(), ShouldEqual, "TELNET")
			})

			Convey("It should return the expected string for an unknown value", func() {
				So(Protocol(0).String(), ShouldEqual, "UNKNOWN")
			})
		})
	})
}
