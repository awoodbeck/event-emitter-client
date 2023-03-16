// Package main contains client code that consumes event server datagrams and
// generates a report on valid events.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"

	p "github.com/awoodbeck/event-emitter-client/protocol"
)

const (
	desc = `This client initiates communication with an event emitter server and parses a 
finite number of events. After parsing all events, the client prints a report of 
findings answering the following questions:

	* What are the top 5 SSH passwords?
	* What are the top 5 SSH usernames?
	* What are the top 5 TELNET passwords?
	* What are the top 5 TELNET usernames?
	* What are the top 30 user-agents in HTTP events?
	* What are the top 20 emails in SMTP?
	* Who are the top 15 submitters?
	* What events did <ip-detail> submit?

`
	labelColor       = 32
	minDatagramBytes = 512
	maxDatagramBytes = 65535
)

func main() {
	var (
		address   = flag.String("address", "localhost:1035", "event server host:port")
		cache     = flag.Int("cache", 20, "MB of RAM to use for caching datagrams (min 1)")
		datagrams = flag.Int("datagrams", 37529, "datagrams to read from event server")
		detailIP  = flag.String("ip-detail", "1.2.3.4", "detail events submitted by a given IP")
		size      = flag.Int("datagram-size", minDatagramBytes,
			fmt.Sprintf("maximum UDP datagram size (min %d; max %d)", minDatagramBytes, maxDatagramBytes),
		)
		verbose = flag.Bool("v", false, "enable verbose (debug) output")
	)
	flag.Usage = func() {
		_, _ = fmt.Fprint(flag.CommandLine.Output(), desc)
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	detailAddr, err := netip.ParseAddr(*detailIP)
	if err != nil {
		log.Warnf("parsing detail IP: %v", err)
	}

	if err = run(*address, *datagrams, *size, *cache, detailAddr); err != nil {
		log.Error(err)
	}
}

func collectEvents(
	ctx context.Context, conn net.Conn, datagrams, size, cache int,
) ([]*p.Event, error) {
	switch {
	case datagrams < 1:
		return nil, fmt.Errorf("no datagrams read from the server")
	case size < minDatagramBytes:
		log.Warnf("%d is below the minimum datagram size; defaulting to %d", size, minDatagramBytes)
		size = minDatagramBytes
	case size > maxDatagramBytes:
		log.Warnf("%d exceeds the maximum datagram size; defaulting to %d", size, maxDatagramBytes)
		size = maxDatagramBytes
	}

	// Decouple datagram reading from parsing, since the latter will likely take
	// longer on some systems (e.g., Linux in Docker on an M1 Mac). At minimum,
	// use 1MB of RAM to cache incoming datagrams.
	if cache < 1 {
		cache = 1
	}
	chDatagrams := make(chan io.Reader, (cache<<20)/size)
	go readDatagrams(ctx, conn, chDatagrams, size)

	// The server needs to know our address before it can emit events to us.
	// Since UDP is stateless, we need to reach out first. We're already
	// listening, minimizing the chance we'll miss any datagrams.
	n, err := conn.Write([]byte("Feed me, Seymour!"))
	if err != nil {
		return nil, fmt.Errorf("writing introduction: %w", err)
	}
	log.Debugf("wrote %d-byte introduction to the server", n)

	var (
		events []*p.Event
		ok     bool
		r      io.Reader
	)

OUTER:
	for i := 1; i <= datagrams; i++ {
		select {
		case <-ctx.Done():
			break OUTER
		case r, ok = <-chDatagrams:
			if !ok {
				log.Debug("datagram channel closed")
				break OUTER
			}
		}

		progress(i, datagrams)

		e := new(p.Event)
		switch _, err = e.ReadFrom(r); {
		case err != nil:
			return nil, err
		case !e.Valid():
			log.Warnf("event %s is invalid; discarding it", e.EventUUID.String())
			continue
		}

		events = append(events, e)
	}

	return events, nil
}

// columns returns the number of columns in the current terminal window.
func columns() int {
	var sz struct {
		_    uint16
		cols uint16
		_    uint16
		_    uint16
	}

	// Considering I was provided event servers for macOS and Linux, I'm going
	// to assume the client runs on one of those two OSes. I'm not positive this
	// works on Windows. We may need to do this a bit differently to get the
	// window size from PowerShell or the like on Windows. But this works for
	// macOS and Linux.
	_, _, _ = syscall.Syscall(
		syscall.SYS_IOCTL,
		os.Stdout.Fd(),
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(&sz)),
	)

	return int(sz.cols)
}

// progress writes a progress bar to os.Stdout.
func progress(step, total int) {
	var (
		// Calculating the columns with each call allows the graph to resize as
		// the terminal resizes while running. Most users won't notice, but it's
		// a detail that makes me happy and the performance hit is negligible.
		width = columns() - 35
		done  = width * step / total
		todo  = width - done
	)

	if width <= 0 {
		// no room to render the progress bar
		return
	}

	if step == 1 {
		fmt.Println()
	}
	fmt.Printf(
		"\r\u001b[%[1]dmProgress:\u001b[0m |%[2]s%[3]s| \u001b[%[1]dm%5.1[4]f%% Complete\u001b[0m",
		labelColor,
		strings.Repeat("#", done),
		strings.Repeat("-", todo),
		100*float64(step)/float64(total),
	)
	if step == total {
		fmt.Println()
		fmt.Println()
	}
}

// readDatagrams reads datagrams up to the given size, and writes them wrapped
// in a bytes.Buffer to the datagrams channel.
func readDatagrams(ctx context.Context, conn net.Conn, chDatagrams chan<- io.Reader, size int) {
	defer close(chDatagrams)

	log.Debug("reading datagrams from the server")

	for {
		b := make([]byte, size)
		n, err := conn.Read(b)
		switch {
		case errors.Is(err, net.ErrClosed):
			log.Debug("connection closed")
			return
		case err != nil:
			log.Errorf("reading %d bytes from socket: %v", n, err)
			continue
		}

		select {
		case <-ctx.Done():
			return
		case chDatagrams <- bytes.NewBuffer(b[:n]):
		}
	}
}

// run establishes a connection to the event server, reads and parses events,
// and renders a report of findings.
func run(address string, datagrams, size, cache int, ipDetail netip.Addr) error {
	if address == "" {
		return fmt.Errorf("server address is required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		cancel()
		log.Debug("context canceled")
	}()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", address)
	if err != nil {
		return fmt.Errorf("dialing %q: %w", address, err)
	}
	defer func() { _ = conn.Close() }()

	log.Infof("collecting events from %q", address)
	events, err := collectEvents(ctx, conn, datagrams, size, cache)
	if err != nil {
		return fmt.Errorf("collecting events: %w", err)
	}

	log.Infof("received %d events", len(events))
	fmt.Print()

	report, err := (&findings{Events: events}).report(ipDetail)
	if err != nil {
		return fmt.Errorf("generating report: %w", err)
	}

	fmt.Printf("\n\n%s\n\n", report)

	return nil
}
