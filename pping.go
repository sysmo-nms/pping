package main

import "fmt"
import "flag"
import "bytes"
import "errors"
import "net"
import "os"
import "time"

// used to identify icmp reply from threads
var packetId int

// ICMP
const (
    icmpv4EchoRequest = 8
    icmpv4EchoReply   = 0
    icmpv6EchoRequest = 128
    icmpv6EchoReply   = 129
)

type icmpMessage struct {
    Type     int             // type
    Code     int             // code
    Checksum int             // checksum
    Body     icmpMessageBody // body
}

type icmpMessageBody interface {
    Len() int
    Marshal() ([]byte, error)
}

// ARGUMENTS HANDLING BEGIN
var VersionFlag     bool
var HostFlag        string
var WarningFlag     int64
var CriticalFlag    int64
var SourceFlag      string
var NumberFlag      int
var IntervalFlag    int
var TtlFlag         int
var TimeoutFlag     int

/* TODO flags
    -w
    -c
    -s
    -n
    -i
    -l
*/
func init() {
    flag.BoolVar(&VersionFlag,  "version",  false, "Show version")
    flag.StringVar(&HostFlag,   "host",     "", "Target")
    flag.IntVar(&TimeoutFlag,   "timeout",  0, "Timeout")
    flag.Int64Var(&WarningFlag, "warning",  200000000, "responce delay warning in nanoseconds")
    flag.Int64Var(&CriticalFlag,"critical", 500000000, "responce delay critical in nanoseconds")
    flag.StringVar(&SourceFlag, "source",   "", "From host or ip")
    flag.IntVar(&NumberFlag,    "number",   5, "Number of packets to send")
    flag.IntVar(&IntervalFlag,  "interval", 80000, "Send packet interval")
    flag.IntVar(&TtlFlag,       "ttl",      0, "TTL on outgoing packets")
}

func parseFlags() {
    flag.Parse()

    if VersionFlag == true {
        printVersion()
        os.Exit(0)
    } else if HostFlag == "" || TimeoutFlag == 0 { // MINIMUM MANDATORY
        flag.PrintDefaults()
        os.Exit(2)
    }
}
// ARGUMENTS HANDLING END

func printVersion() {
    fmt.Printf("go_check_icmp V0.1\n")
}

// ICMP UTILS
// Marshal returns the binary enconding of the ICMP echo request or
// reply message m.
func (m *icmpMessage) Marshal() ([]byte, error) {
    b := []byte{byte(m.Type), byte(m.Code), 0, 0}
    if m.Body != nil && m.Body.Len() != 0 {
        mb, err := m.Body.Marshal()
        if err != nil {
            return nil, err
        }
        b = append(b, mb...)
    }
    switch m.Type {
    case icmpv6EchoRequest, icmpv6EchoReply:
        return b, nil
    }
    csumcv := len(b) - 1 // checksum coverage
    s := uint32(0)
    for i := 0; i < csumcv; i += 2 {
        s += uint32(b[i+1])<<8 | uint32(b[i])
    }
    if csumcv&1 == 0 {
        s += uint32(b[csumcv])
    }
    s = s>>16 + s&0xffff
    s = s + s>>16
    // Place checksum back in header; using ^= avoids the
    // assumption the checksum bytes are zero.
    b[2] ^= byte(^s & 0xff)
    b[3] ^= byte(^s >> 8)
    return b, nil
}

// parseICMPMessage parses b as an ICMP message.
func parseICMPMessage(b []byte) (*icmpMessage, error) {
    msglen := len(b)
    if msglen < 4 {
        return nil, errors.New("message too short")
    }
    m := &icmpMessage{Type: int(b[0]), Code: int(b[1]), Checksum: int(b[2])<<8 | int(b[3])}
    if msglen > 4 {
        var err error
        switch m.Type {
        case icmpv4EchoRequest, icmpv4EchoReply, icmpv6EchoRequest, icmpv6EchoReply:
            m.Body, err = parseICMPEcho(b[4:])
            if err != nil {
                return nil, err
            }
        }
    }
    return m, nil
}

// imcpEcho represenets an ICMP echo request or reply message body.
type icmpEcho struct {
    ID   int    // identifier
    Seq  int    // sequence number
    Data []byte // data
}

func (p *icmpEcho) Len() int {
    if p == nil {
        return 0
    }
    return 4 + len(p.Data)
}

// Marshal returns the binary enconding of the ICMP echo request or
// reply message body p.
func (p *icmpEcho) Marshal() ([]byte, error) {
    b := make([]byte, 4+len(p.Data))
    b[0], b[1] = byte(p.ID>>8), byte(p.ID&0xff)
    b[2], b[3] = byte(p.Seq>>8), byte(p.Seq&0xff)
    copy(b[4:], p.Data)
    return b, nil
}

// parseICMPEcho parses b as an ICMP echo request or reply message body.
func parseICMPEcho(b []byte) (*icmpEcho, error) {
    bodylen := len(b)
    p := &icmpEcho{ID: int(b[0])<<8 | int(b[1]), Seq: int(b[2])<<8 | int(b[3])}
    if bodylen > 4 {
        p.Data = make([]byte, bodylen-4)
        copy(p.Data, b[4:])
    }
    return p, nil
}

func Ping(address string, timeout int, identifier string) (err error, alive bool) {
    err     = Pinger(address, timeout, identifier)
    alive   = err == nil
    return err, alive
}

func Pinger(address string, timeout int, identifier string) (err error) {
    c, err := net.Dial("ip4:icmp", address)
    if err != nil {
        return
    }
    c.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
    defer c.Close()

    typ := icmpv4EchoRequest
    xid, xseq := os.Getpid()&0xffff, 1
    wb, err := (&icmpMessage{
        Type: typ, Code: 0,
        Body: &icmpEcho{
            ID: xid, Seq: xseq,
            Data: bytes.Repeat([]byte(identifier), 3),
        },
    }).Marshal()
    if err != nil {
        return
    }
    if _, err = c.Write(wb); err != nil {
        return
    }
    var m *icmpMessage
    rb := make([]byte, 20+len(wb))
    for {
        if _, err = c.Read(rb); err != nil {
            return
        }
        rb = ipv4Payload(rb)
        if m, err = parseICMPMessage(rb); err != nil {
            return
        }
        switch m.Type {
        case icmpv4EchoRequest, icmpv6EchoRequest:
            continue
        }
        break
    }
    return
}

func ipv4Payload(b []byte) []byte {
    if len(b) < 20 {
        return b
    }
    hdrlen := int(b[0]&0x0f) << 2
    return b[hdrlen:]
}


func pingThread() (err error, alive bool, status string) {
    identifier      := fmt.Sprintf("noctopus-ping%d", packetId)
    packetId        = packetId + 1
    startCheck      := time.Now()
    err, alive      = Ping(HostFlag, TimeoutFlag, identifier)
    checkLatency    := time.Since(startCheck)
    msLatency       := checkLatency.Nanoseconds()
    if msLatency < WarningFlag {
        status = "ok"
    } else if msLatency < CriticalFlag {
        status = "warning"
    } else {
        status = "critical"
    }
    return err, alive, status
}

// MAIN
func main() {
    parseFlags()
    // TODO loop over -n number of check each -i intervals
    // -w -c percent failures on all checks
    packetId = 0
    err, alive, status := pingThread()

    if alive == true {
        if status == "ok" { // -w -c 
            fmt.Printf("ICMP OK: success")
        } else if status == "warning" {
            fmt.Printf("ICMP WARNING: warning")
        } else if status == "critical" {
            fmt.Printf("ICMP CRITICAL: critical")
        }
    } else {
        fmt.Printf("ICMP CRITICAL: %v", err.Error())
    }
}
