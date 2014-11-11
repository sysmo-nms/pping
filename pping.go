package main

import "fmt"
import "flag"
import "bytes"
import "errors"
import "net"
import "os"
import "time"

var VersionFlag     bool
var HostFlag        string
var SourceFlag      string
var NumberFlag      int
var IntervalFlag    int
var TtlFlag         int
var TimeoutFlag     int
var SizeFlag        int
var Ip6Flag         bool

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

type ppingEvent struct {
    From    string
    SeqId   int
}

type icmpMessageBody interface {
    Len()           int
    Marshal()       ([]byte, error)
    GetProcID()     int
    GetSequenceID() int
}

func main() {
    parseFlags()
    host     := HostFlag
    number   := NumberFlag
    timeout  := time.Duration(TimeoutFlag)  * time.Millisecond
    interval := time.Duration(IntervalFlag) * time.Millisecond
    size     := SizeFlag

    var err   error
    var conn  net.Conn
    var requestCode int
    var replyCode   int
    if Ip6Flag == true {
        requestCode = icmpv6EchoRequest
        replyCode   = icmpv6EchoReply
        conn, err = net.Dial("ip6:icmp", host)
    } else {
        requestCode = icmpv4EchoRequest
        replyCode   = icmpv4EchoReply
        conn, err = net.Dial("ip4:icmp", host)
    }
    if err != nil { fmt.Println(err); os.Exit(1)}

    procId := os.Getpid()&0xffff
    var eventchan chan ppingEvent = make(chan ppingEvent)

    go icmpEchoReceiver(conn,eventchan,replyCode,number,procId)
    go icmpEchoSender(conn,eventchan,requestCode,number,procId,size,interval)

    var msg ppingEvent
    fmt.Println("timeout: ",timeout)
    for {
        msg = <- eventchan
        if msg.From == "fromReceiver" {
            fmt.Println("from receiver", msg.SeqId)
            number -= 1
        } else if msg.From == "fromSender" {
            fmt.Println("from sender", msg.SeqId)
        }
        if number == 0 { break }
    }
    conn.Close()
    fmt.Println("ok")
}


func icmpEchoSender(
    conn        net.Conn,
    eventchan   chan ppingEvent,
    requestCode int,
    number      int,
    procId      int,
    size        int,
    interval    time.Duration) {
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
        eventchan <- ppingEvent{From: "fromSender", SeqId: seqId}
        time.Sleep(interval)
    }
}

func icmpEchoReceiver(
        conn        net.Conn,
        eventchan   chan ppingEvent,
        replyCode   int,
        number      int,
        procId      int) {

    icmpReplyBuffer := make([]byte, icmpPacketMaxSize)

    var seqId   int
    var reply   *icmpMessage
    var icmp4Payload []byte
    var read    int
    var err     error

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
                eventchan <- ppingEvent{From: "fromReceiver", SeqId: seqId}
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
