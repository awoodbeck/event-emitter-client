# About
I was asked to provide an example client for ingesting UDP datagrams, computing statistics about
those datagrams, and outputting the results to standard output. Since this is a command line client,
I used ANSI colors and animation to make it a bit more pleasant to use.

I don't contend this is the best way to ingest UDP packets, but it's a viable way to do so. Because
I was having fun with this, I used a lexer and parser to parse the payload. That's a bit overkill
for simple payloads, but it scales well as payload complexity increases.

## Protocol
The server sends [events](protocol/event.go#L55) over UDP that conform to this binary (BigEndian) structure:

| Description          |          Bytes |
|----------------------|---------------:|
| Node ID              |              2 |
| EPOC TimeStamp       |              4 |
| Payload Size         |              2 |
| UUID                 |             16 |
| Payload              | _payload size_ |
| Protocol<sup>1</sup> |              2 |
| Submitter IP         |              4 |
| CRC32                |              4 |

<sup>1</sup> [Protocol constants](protocol/event.go#L12)

# Assumptions
* The client runs on Linux or macOS, primarily because the server binaries used to create this client were targeted at these OSes
  * The only likely Windows limitation in the client code are system calls to determine terminal window sizing
* Go 1s .19+ is in the PATH
  * Go 1.19 is required due to use of new [AppendByteOrder](https://pkg.go.dev/encoding/binary#AppendByteOrder) interface

# Build and Run the Client
Nothing special is required here. Simply `go build` the source code.
```shell
$ go build -o bin/client *.go
$ ./bin/client -h
This client initiates communication with an event server and parses a finite 
number of events. After parsing all events, the client prints a report of 
findings answering the following questions:

        * What are the top 5 SSH passwords?
        * What are the top 5 SSH usernames?
        * What are the top 5 TELNET passwords?
        * What are the top 5 TELNET usernames?
        * What are the top 30 user-agents in HTTP events?
        * What are the top 20 emails in SMTP?
        * Who are the top 15 submitters?
        * What events did <ip-detail> submit?

Usage of ./bin/client:
  -address string
        event server host:port (default "localhost:1035")
  -cache int
        MB of RAM to use for caching datagrams (min 1) (default 20)
  -datagram-size int
        maximum UDP datagram size (min 512; max 65535) (default 512)
  -datagrams int
        datagrams to read from event server (default 37529)
  -ip-detail string
        detail events submitted by a given IP (default "1.2.3.4")
  -v    enable verbose (debug) output
```

The flag defaults should be sufficient if you're running the emitter server
using its defaults on the same system.

# Bonus
The CRC32 validation occurs in the `protocol.Event.Valid()` method.
