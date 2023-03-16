package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	p "github.com/awoodbeck/event-emitter-client/protocol"
)

func Test_collectEvents(t *testing.T) {
	Convey("Given a net.Conn to an event server", t, func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		eventCount := len(validEvents) + 20
		conn := &mockConn{maxEvents: int64(eventCount), events: validEvents}

		Convey("When calling the collectEvents function", func() {
			Convey("It should return a slice of expected events", func() {
				actual, err := collectEvents(ctx, conn, eventCount, 512, 0)
				So(err, ShouldBeNil)

				// slice contains the events in the order they were sent by the
				// mockConn
				expected := make([]*p.Event, 0, eventCount)
				for i := eventCount; i > 0; i-- {
					expected = append(expected, conn.events[i%len(conn.events)])
				}

				// which should be the same order they were received
				So(actual, ShouldResemble, expected)
			})

			Convey("It should succeed even if the datagram size is too small", func() {
				actual, err := collectEvents(ctx, conn, eventCount, minDatagramBytes-1, 0)
				So(err, ShouldBeNil)

				expected := make([]*p.Event, 0, eventCount)
				for i := eventCount; i > 0; i-- {
					expected = append(expected, conn.events[i%len(conn.events)])
				}

				So(actual, ShouldResemble, expected)
			})

			Convey("It should succeed even if the datagram size is too large", func() {
				actual, err := collectEvents(ctx, conn, eventCount, maxDatagramBytes+1, 0)
				So(err, ShouldBeNil)

				expected := make([]*p.Event, 0, eventCount)
				for i := eventCount; i > 0; i-- {
					expected = append(expected, conn.events[i%len(conn.events)])
				}

				So(actual, ShouldResemble, expected)
			})

			Convey("It should return a slice even on short read of events", func() {
				actual, err := collectEvents(ctx, conn, eventCount+1, 512, 0)
				So(err, ShouldBeNil)

				expected := make([]*p.Event, 0, eventCount)
				for i := eventCount; i > 0; i-- {
					expected = append(expected, conn.events[i%len(conn.events)])
				}

				So(actual, ShouldResemble, expected)
			})

			Convey("It should return an empty slice when the context is canceled before reading", func() {
				cancel()
				actual, err := collectEvents(ctx, conn, eventCount, 512, 0)
				So(err, ShouldBeNil)
				So(actual, ShouldBeEmpty)
			})

			Convey("It should return an empty slice when all that's receives is invalid events", func() {
				conn.events = invalidEvents
				actual, err := collectEvents(ctx, conn, eventCount, 512, 0)
				So(err, ShouldBeNil)
				So(actual, ShouldBeEmpty)
			})

			Convey("It should return an error if datagrams is zero", func() {
				_, err := collectEvents(ctx, conn, 0, 512, 0)
				So(err, ShouldBeError)
			})

			Convey("It should return an error upon a conn.Write error", func() {
				conn.wantWriteErr = fmt.Errorf("some error")
				_, err := collectEvents(ctx, conn, eventCount, 512, 0)
				So(err, ShouldBeError)
			})
		})
	})
}

func Test_readDatagrams(t *testing.T) {
	Convey("Given a net.Conn to an event server", t, func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		conn := &mockConn{maxEvents: 4, events: validEvents}

		Convey("When calling the readDatagrams function", func() {
			Convey("It should read datagrams from the net.Conn", func() {
				chDatagrams := make(chan io.Reader)
				go readDatagrams(ctx, conn, chDatagrams, 512)

				for i := 4; i > 0; i-- {
					r := <-chDatagrams
					buf := new(bytes.Buffer)
					n, err := io.Copy(buf, r)
					So(err, ShouldBeNil)
					So(n, ShouldBeGreaterThan, 0)

					// Verify we read the bytes completely
					mb, err := (conn.events[i%len(conn.events)]).MarshalBinary()
					So(err, ShouldBeNil)
					So(buf.Bytes(), ShouldResemble, mb)
				}
			})

			Convey("It should read datagrams from the net.Conn, logging errors", func() {
				conn.wantReadErr = fmt.Errorf("some error")

				chDatagrams := make(chan io.Reader)
				go readDatagrams(ctx, conn, chDatagrams, 512)

				for {
					r, ok := <-chDatagrams
					if !ok {
						break
					}

					n, err := io.Copy(io.Discard, r)
					So(err, ShouldBeNil)
					So(n, ShouldBeGreaterThan, 0)
				}
			})

			Convey("It should return when the context is closed", func() {
				done := make(chan struct{})

				go func() {
					readDatagrams(ctx, conn, make(chan io.Reader), 512)
					close(done)
				}()

				// readDatagrams has read the first datagram, and is selecting
				// on the context's Done channel and the datagrams channel at
				// this point. Cancel the context, which should make it return,
				// closing the done channel.
				cancel()
				<-done
			})
		})
	})
}

func Test_run(t *testing.T) {
	Convey("Given the address of an event server", t, func() {
		Convey("When calling the run function", func() {
			Convey("It should succeed", func() {
				addr, err := udpServer(validEvents)
				So(err, ShouldBeNil)

				err = run(
					addr.String(),
					len(validEvents),
					minDatagramBytes,
					0,
					netip.MustParseAddr("106.54.93.84"),
				)
				So(err, ShouldBeNil)
			})

			Convey("It should return an error given an empty address", func() {
				err := run("", 37529, minDatagramBytes, 0, netip.MustParseAddr("106.54.93.84"))
				So(err, ShouldBeError)
			})

			Convey("It should return an error when expecting 0 datagrams", func() {
				addr, err := udpServer(validEvents)
				So(err, ShouldBeNil)

				err = run(
					addr.String(),
					0,
					minDatagramBytes,
					0,
					netip.MustParseAddr("106.54.93.84"),
				)
				So(err, ShouldBeError)
			})

			Convey("It should return an error if encountering an error generating the report", func() {
				events := validEvents[:len(validEvents)-1]
				addr, err := udpServer(events)
				So(err, ShouldBeNil)

				err = run(
					addr.String(),
					len(events),
					minDatagramBytes,
					0,
					netip.MustParseAddr("106.54.93.84"),
				)
				So(err, ShouldBeError)
			})

			Convey("It should return an error if the report has no SSH events", func() {
				events := make([]*p.Event, 0, len(validEvents))
				for _, e := range validEvents {
					if e.Protocol == p.SSH {
						continue
					}

					events = append(events, e)
				}

				addr, err := udpServer(events)
				So(err, ShouldBeNil)

				err = run(
					addr.String(),
					len(events),
					minDatagramBytes,
					0,
					netip.MustParseAddr("106.54.93.84"),
				)
				So(err, ShouldBeError)
			})

			Convey("It should return an error if the report has no TELNET events", func() {
				events := make([]*p.Event, 0, len(validEvents))
				for _, e := range validEvents {
					if e.Protocol == p.TELNET {
						continue
					}

					events = append(events, e)
				}

				addr, err := udpServer(events)
				So(err, ShouldBeNil)

				err = run(
					addr.String(),
					len(events),
					minDatagramBytes,
					0,
					netip.MustParseAddr("106.54.93.84"),
				)
				So(err, ShouldBeError)
			})

			Convey("It should return an error if the report has no HTTP events", func() {
				events := make([]*p.Event, 0, len(validEvents))
				for _, e := range validEvents {
					if e.Protocol == p.HTTP {
						continue
					}

					events = append(events, e)
				}

				addr, err := udpServer(events)
				So(err, ShouldBeNil)

				err = run(
					addr.String(),
					len(events),
					minDatagramBytes,
					0,
					netip.MustParseAddr("106.54.93.84"),
				)
				So(err, ShouldBeError)
			})

			Convey("It should return an error if the report has no SMTP events", func() {
				events := make([]*p.Event, 0, len(validEvents))
				for _, e := range validEvents {
					if e.Protocol == p.SMTP {
						continue
					}

					events = append(events, e)
				}

				addr, err := udpServer(events)
				So(err, ShouldBeNil)

				err = run(
					addr.String(),
					len(events),
					minDatagramBytes,
					0,
					netip.MustParseAddr("106.54.93.84"),
				)
				So(err, ShouldBeError)
			})
		})
	})
}

func udpServer(events []*p.Event) (net.Addr, error) {
	s, err := net.ListenPacket("udp", "localhost:")
	if err != nil {
		return nil, fmt.Errorf("binding to udp localhost: %w", err)
	}

	go func() {
		_, clientAddr, err := s.ReadFrom(make([]byte, 1024))
		if err != nil {
			panic(err)
		}

		for _, event := range events {
			b, err := event.MarshalBinary()
			if err != nil {
				panic(err)
			}
			if _, err = s.WriteTo(b, clientAddr); err != nil {
				panic(err)
			}
		}

		_ = s.Close()
	}()

	return s.LocalAddr(), nil
}

// mockConn implements a subset of the net.Conn interface.
type mockConn struct {
	net.Conn

	events       []*p.Event
	maxEvents    int64
	wantReadErr  error
	wantWriteErr error
}

// Read implements the io.Reader interface.
func (c *mockConn) Read(b []byte) (int, error) {
	count := int(atomic.LoadInt64(&c.maxEvents))
	if count <= 0 {
		return 0, net.ErrClosed
	}
	atomic.AddInt64(&c.maxEvents, -1)

	if c.wantReadErr != nil && count == 2 {
		// we want an error just before the last event is read
		return 0, c.wantReadErr
	}

	mb, err := (c.events[count%len(c.events)]).MarshalBinary()
	if err != nil {
		return 0, err
	}

	copy(b, mb)

	return len(mb), nil
}

// Write implements the io.Writer interface.
func (c *mockConn) Write(b []byte) (int, error) {
	if c.wantWriteErr != nil {
		return 0, c.wantWriteErr
	}

	return len(b), nil
}

var invalidEvents = []*p.Event{
	{
		NodeID:    0x7,
		TimeStamp: 0x5f879100,
		Size:      0x1c,
		EventUUID: p.UUID{
			TimeLow:          0x36666566,
			TimeMid:          0x6435,
			TimeHiAndVersion: 0x6236,
			ClockSeqHiAndRes: 0x2d,
			ClockSeqLow:      0x35,
			Node:             [6]uint8{0x30, 0x64, 0x65, 0x2d, 0x31, 0x31},
		},
		Payload: map[string]string{
			"email": "chloesmith263@test.net",
		},
		Protocol:     0x11,
		Submitter:    0xe914b560,
		CheckSum:     0xa1c010c3,
		PayloadBytes: []uint8{0x65, 0x6d, 0x61, 0x69, 0x6c, 0x3a, 0x63, 0x68, 0x6c, 0x6f, 0x65, 0x73, 0x6d, 0x69, 0x74, 0x68, 0x32, 0x36, 0x33, 0x40, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x6e, 0x65, 0x74},
		IP:           netip.MustParseAddr("233.20.181.96"),
	},
	{
		NodeID:    0x1,
		TimeStamp: 0x5f7e5680,
		Size:      0x23,
		EventUUID: p.UUID{
			TimeLow:          0x36666566,
			TimeMid:          0x6539,
			TimeHiAndVersion: 0x6465,
			ClockSeqHiAndRes: 0x2d,
			ClockSeqLow:      0x35,
			Node:             [6]uint8{0x30, 0x64, 0x65, 0x2d, 0x31, 0x31},
		},
		Payload: map[string]string{
			"password": "Jackallava",
			"username": "elijah",
		},
		Protocol:  0x31,
		Submitter: 0x6a436f0f,
		CheckSum:  0x8da96d65,
		PayloadBytes: []uint8{
			0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x3a, 0x65, 0x6c, 0x69, 0x6a, 0x61,
			0x68, 0x2c, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x3a, 0x4a, 0x61, 0x63,
			0x6b, 0x61, 0x6c, 0x6c, 0x61, 0x76, 0x61,
		},
		IP: netip.MustParseAddr("106.67.111.15"),
	},
}

var validEvents = []*p.Event{
	{
		NodeID:    0xa,
		TimeStamp: 0x5f879100,
		Size:      0x1c,
		EventUUID: p.UUID{
			TimeLow:          0x36666566,
			TimeMid:          0x6435,
			TimeHiAndVersion: 0x6236,
			ClockSeqHiAndRes: 0x2d,
			ClockSeqLow:      0x35,
			Node:             [6]uint8{0x30, 0x64, 0x65, 0x2d, 0x31, 0x31},
		},
		Payload: map[string]string{
			"email": "chloesmith263@test.net",
		},
		Protocol:     0x11,
		Submitter:    0xe914b560,
		CheckSum:     0xa1c010c3,
		PayloadBytes: []uint8{0x65, 0x6d, 0x61, 0x69, 0x6c, 0x3a, 0x63, 0x68, 0x6c, 0x6f, 0x65, 0x73, 0x6d, 0x69, 0x74, 0x68, 0x32, 0x36, 0x33, 0x40, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x6e, 0x65, 0x74},
		IP:           netip.MustParseAddr("233.20.181.96"),
	},
	{
		NodeID:    0x2,
		TimeStamp: 0x5f7e5680,
		Size:      0x23,
		EventUUID: p.UUID{
			TimeLow:          0x36666566,
			TimeMid:          0x6539,
			TimeHiAndVersion: 0x6465,
			ClockSeqHiAndRes: 0x2d,
			ClockSeqLow:      0x35,
			Node:             [6]uint8{0x30, 0x64, 0x65, 0x2d, 0x31, 0x31},
		},
		Payload: map[string]string{
			"password": "Jackallava",
			"username": "elijah",
		},
		Protocol:  0x31,
		Submitter: 0x6a436f0f,
		CheckSum:  0x8da96d65,
		PayloadBytes: []uint8{
			0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x3a, 0x65, 0x6c, 0x69, 0x6a, 0x61,
			0x68, 0x2c, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x3a, 0x4a, 0x61, 0x63,
			0x6b, 0x61, 0x6c, 0x6c, 0x61, 0x76, 0x61,
		},
		IP: netip.MustParseAddr("106.67.111.15"),
	},
	{
		NodeID:    0x4,
		TimeStamp: 0x5f751c00,
		Size:      0x28,
		EventUUID: p.UUID{
			TimeLow:          0x36666566,
			TimeMid:          0x6564,
			TimeHiAndVersion: 0x3538,
			ClockSeqHiAndRes: 0x2d,
			ClockSeqLow:      0x35,
			Node:             [6]uint8{0x30, 0x64, 0x65, 0x2d, 0x31, 0x31},
		},
		Payload: map[string]string{
			"password": "Shriekerlavender",
			"username": "aiden",
		},
		Protocol:  0x31,
		Submitter: 0xda70e880,
		CheckSum:  0xf1075325,
		PayloadBytes: []uint8{
			0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x3a, 0x61, 0x69, 0x64, 0x65, 0x6e,
			0x2c, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x3a, 0x53, 0x68, 0x72, 0x69,
			0x65, 0x6b, 0x65, 0x72, 0x6c, 0x61, 0x76, 0x65, 0x6e, 0x64, 0x65, 0x72,
		},
		IP: netip.MustParseAddr("218.112.232.128"),
	},
	{
		NodeID:    0x9,
		TimeStamp: 0x5f824b00,
		Size:      0x23,
		EventUUID: p.UUID{
			TimeLow:          0x36666566,
			TimeMid:          0x6630,
			TimeHiAndVersion: 0x3363,
			ClockSeqHiAndRes: 0x2d,
			ClockSeqLow:      0x35,
			Node:             [6]uint8{0x30, 0x64, 0x65, 0x2d, 0x31, 0x31},
		},
		Payload: map[string]string{
			"password": "Lasherfan",
			"username": "william",
		},
		Protocol:  0x23,
		Submitter: 0x82156050,
		CheckSum:  0xac412739,
		PayloadBytes: []uint8{
			0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x3a, 0x77, 0x69, 0x6c, 0x6c, 0x69,
			0x61, 0x6d, 0x2c, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x3a, 0x4c, 0x61,
			0x73, 0x68, 0x65, 0x72, 0x66, 0x61, 0x6e,
		},
		IP: netip.MustParseAddr("130.21.96.80"),
	},
	{
		NodeID:    0xb,
		TimeStamp: 0x5f84ee00,
		Size:      0x89,
		EventUUID: p.UUID{
			TimeLow:          0x65613630,
			TimeMid:          0x3432,
			TimeHiAndVersion: 0x3865,
			ClockSeqHiAndRes: 0x2d,
			ClockSeqLow:      0x35,
			Node:             [6]uint8{0x33, 0x33, 0x38, 0x2d, 0x31, 0x31},
		},
		Payload: map[string]string{
			"user-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36 OPR/47.0.2631.55",
		},
		Protocol:  0xa,
		Submitter: 0x47c1f9e1,
		CheckSum:  0x941f9a5b,
		PayloadBytes: []uint8{
			0x75, 0x73, 0x65, 0x72, 0x2d, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x4d, 0x6f, 0x7a,
			0x69, 0x6c, 0x6c, 0x61, 0x2f, 0x35, 0x2e, 0x30, 0x20, 0x28, 0x57, 0x69, 0x6e, 0x64,
			0x6f, 0x77, 0x73, 0x20, 0x4e, 0x54, 0x20, 0x31, 0x30, 0x2e, 0x30, 0x3b, 0x20, 0x57,
			0x4f, 0x57, 0x36, 0x34, 0x29, 0x20, 0x41, 0x70, 0x70, 0x6c, 0x65, 0x57, 0x65, 0x62,
			0x4b, 0x69, 0x74, 0x2f, 0x35, 0x33, 0x37, 0x2e, 0x33, 0x36, 0x20, 0x28, 0x4b, 0x48,
			0x54, 0x4d, 0x4c, 0x2c, 0x20, 0x6c, 0x69, 0x6b, 0x65, 0x20, 0x47, 0x65, 0x63, 0x6b,
			0x6f, 0x29, 0x20, 0x43, 0x68, 0x72, 0x6f, 0x6d, 0x65, 0x2f, 0x36, 0x30, 0x2e, 0x30,
			0x2e, 0x33, 0x31, 0x31, 0x32, 0x2e, 0x37, 0x38, 0x20, 0x53, 0x61, 0x66, 0x61, 0x72,
			0x69, 0x2f, 0x35, 0x33, 0x37, 0x2e, 0x33, 0x36, 0x20, 0x4f, 0x50, 0x52, 0x2f, 0x34,
			0x37, 0x2e, 0x30, 0x2e, 0x32, 0x36, 0x33, 0x31, 0x2e, 0x35, 0x35,
		},
		IP: netip.MustParseAddr("71.193.249.225"),
	},
}
