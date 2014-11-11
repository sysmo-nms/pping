package main

import "fmt"
import "flag"
import "bytes"
import "errors"
import "net"
import "os"
import "time"


// ICMP
const (
    icmpv4EchoRequest = 8
    icmpv4EchoReply   = 0
    icmpv6EchoRequest = 128
    icmpv6EchoReply   = 129
    icmpPacketMaxSize = 65535
)

type icmpMessage struct {
    Type     int             // type
    Code     int             // code
    Checksum int             // checksum
    Body     icmpMessageBody // body
}

type icmpMessageBody interface {
    Len()           int
    Marshal()       ([]byte, error)
    GetProcID()     int
    GetSequenceID() int
}

type controlMsg struct {
    From    string
    SeqId   int
}

type controlReply struct {
    PercentLoss int
    AverageTime int
    MaxTime     int
    MinTime     int
}

var VersionFlag     bool
var HostFlag        string
var SourceFlag      string
var NumberFlag      int
var IntervalFlag    int
var TtlFlag         int
var TimeoutFlag     int
var SizeFlag        int
var Ip6Flag         bool

func icmpEchoControl(
        conn        net.Conn,
        number      int,
        timeout     time.Duration,
        eventchan   chan controlMsg,
        replychan   chan controlReply) {

    var msg controlMsg
    for {
        msg = <- eventchan
        if msg.From == "fromMain" {
            number -= 1
        }
        if number == 0 { break }
    }
    conn.Close()
    replychan <- controlReply{
        PercentLoss: 0,
        AverageTime: 100,
        MaxTime:     140,
        MinTime:     50,
    }
}

func icmpEchoSender(
    conn        net.Conn,
    requestCode int,
    procId      int,
    number      int,
    size        int,
    interval    time.Duration,
    control     chan controlMsg) {
    var err error
    for i := 0; i < number; i++ {
        seqId := i + 1
        wb, _ := (&icmpMessage{
            Type: requestCode,
            Code: 0,
            Body: &icmpEcho{
                ID:     procId,
                Seq:    seqId,
                Data:   bytes.Repeat([]byte("g"), size),
            },
        }).Marshal()
        _, err = conn.Write(wb)
        if err != nil { fmt.Println(err); os.Exit(1) }
        control <- controlMsg{From: "fromSender", SeqId: seqId}
        time.Sleep(interval)
    }
}

func main() {
    parseFlags()
    host     := HostFlag
    number   := NumberFlag
    timeout  := time.Duration(TimeoutFlag) * time.Millisecond
    interval := time.Duration(IntervalFlag) * time.Millisecond
    size     := SizeFlag

    var ipver int
    var err   error
    var conn  net.Conn
    var icmpEchoRequest int
    var icmpEchoReply   int
    if Ip6Flag == true {
        ipver = 6
        icmpEchoRequest = icmpv6EchoRequest
        icmpEchoReply   = icmpv6EchoReply
        conn, err = net.Dial("ip6:icmp", host)
    } else {
        ipver = 4
        icmpEchoRequest = icmpv4EchoRequest
        icmpEchoReply   = icmpv4EchoReply
        conn, err = net.Dial("ip4:icmp", host)
    }

    if err != nil { fmt.Println(err); os.Exit(1)}

    procId          := os.Getpid()&0xffff
    icmpReplyBuffer := make([]byte, icmpPacketMaxSize)

    var seqId int
    var read  int
    var reply *icmpMessage
    var icmp4Payload []byte

    var eventchan chan controlMsg   = make(chan controlMsg)
    var replychan chan controlReply = make(chan controlReply)
    go icmpEchoControl(conn, number, timeout, eventchan, replychan)
    go icmpEchoSender(conn, icmpEchoRequest, procId, number, size, interval, eventchan)

    fmt.Println(ipver, icmpEchoReply)
    for {
        read, err = conn.Read(icmpReplyBuffer)
        if err != nil { break }
        ipVersion := icmpReplyBuffer[0]>>4

        if ipVersion == 4 {
            if read < 28 { continue }
            // ipHeader = icmpReplyBuffer[0:20]
            icmp4Payload     = icmpReplyBuffer[20:read]
            reply, err       = parseICMPMessage(icmp4Payload)
            switch reply.Type {
            case icmpv4EchoRequest, icmpv6EchoRequest:
                continue
            }
            payload := reply.Body
            if payload.GetProcID() == procId{
                seqId = payload.GetSequenceID()
                eventchan <- controlMsg{From: "fromMain", SeqId: seqId}
            }
            number -= 1
            if number == 0 {
                break
            }

        } else if ipVersion == 6 {
            //ipHeader    = icmpReplyBuffer[0:40]
            //icmpPayload = icmpReplyBuffer[40:read]
            // TODO support v6
            continue
        }
    }

    finalMsg := <- replychan
    fmt.Println("ok", finalMsg)
}

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
    flag.IntVar(&TimeoutFlag,   "timeout",  5000, "Timeout")
    flag.StringVar(&SourceFlag, "source",   "", "From host or ip")
    flag.IntVar(&NumberFlag,    "number",   5, "Number of packets to send")
    flag.IntVar(&IntervalFlag,  "interval", 100, "Send packet interval in millisecond")
    flag.IntVar(&TtlFlag,       "ttl",      0, "TTL on outgoing packets")
    flag.IntVar(&SizeFlag,      "size",     56,"Size of the icmp payload in octets (+8 icmp header)")
    flag.BoolVar(&Ip6Flag,      "ipv6",     false, "Enable version 6 icmp")
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


func printVersion() {
    fmt.Printf("go_check_icmp V0.1\n")
}


/* 
   ICMP UTILS
   Marshal returns the binary enconding of the ICMP echo request or
   reply message m.
*/
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
    m := &icmpMessage{
        Type: int(b[0]),
        Code: int(b[1]),
        Checksum: int(b[2])<<8 | int(b[3]) }
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

func(p *icmpEcho) GetProcID() int {
    return p.ID
}

func(p *icmpEcho) GetSequenceID() int {
    return p.Seq
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
    p := &icmpEcho{
        ID:  int(b[0])<<8 | int(b[1]),
        Seq: int(b[2])<<8 | int(b[3]) }
    if bodylen > 4 {
        p.Data = make([]byte, bodylen-4)
        copy(p.Data, b[4:])
    }
    return p, nil
}

func ipv4Payload(b []byte) []byte {
    if len(b) < 20 {
        return b
    }
    hdrlen := int(b[0]&0x0f) << 2
    return b[hdrlen:]
}

func returnError(err error) {
    fmt.Println("error: ", err)
}
