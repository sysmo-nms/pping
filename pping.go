package main

import "fmt"
import "flag"
import "bytes"
import "errors"
import "net"
import "os"
import "time"

type ppingEvent struct {
    From    string
    SeqId   int
}

func main() {
    parseFlags()
    host     := HostFlag
    counter  := NumberFlag
    timeout  := time.Duration(TimeoutFlag)  * time.Millisecond
    interval := time.Duration(IntervalFlag) * time.Millisecond
    size     := SizeFlag

    var err         error
    var conn        net.Conn
    var requestCode int
    var replyCode   int

    if Ip6Flag == true {
        requestCode = icmpv6EchoRequest
        replyCode   = icmpv6EchoReply
        conn, err   = net.Dial("ip6:icmp", host)
    } else {
        requestCode = icmpv4EchoRequest
        replyCode   = icmpv4EchoReply
        conn, err   = net.Dial("ip4:icmp", host)
    }
    if err != nil { fmt.Println(err); os.Exit(1) }

    procId := os.Getpid()&0xffff

    var eventchan chan ppingEvent = make(chan ppingEvent)
    go icmpEchoReceiver(conn,eventchan,replyCode,counter,procId)
    go icmpEchoSender(conn,eventchan,requestCode,counter,procId,size,interval)

    var eventMsg ppingEvent
    for {
        eventMsg = <- eventchan
        if eventMsg.From == "fromReceiver" {
            fmt.Println("from receiver", eventMsg.SeqId)
            counter -= 1
        } else if eventMsg.From == "fromSender" {
            fmt.Println("from sender", eventMsg.SeqId)
        }
        if counter == 0 { break }
    }
    conn.Close()
    fmt.Println("timeout: ",timeout)
    fmt.Println("ok")
}

func icmpEchoSender(
    conn        net.Conn,
    eventchan   chan ppingEvent,
    requestCode int,
    counter     int,
    procId      int,
    size        int,
    interval    time.Duration) {
    var err error
    for i := 0; i < counter; i++ {
        seqId := i + 1
        pdu, _ := (&icmpMessage{
            Type: requestCode,
            Code: 0,
            Body: &icmpBody{
                ID:     procId,
                Seq:    seqId,
                Data:   bytes.Repeat([]byte("g"), size),
            },
        }).Encode(conn)
        _, err = conn.Write(pdu)
        if err != nil { fmt.Println(err); os.Exit(1) }
        eventchan <- ppingEvent{From: "fromSender", SeqId: seqId}
        time.Sleep(interval)
    }
}

func icmpEchoReceiver(
        conn        net.Conn,
        eventchan   chan ppingEvent,
        replyCode   int,
        counter     int,
        procId      int) {

    icmpBuffer := make([]byte, icmpPacketMaxSize)

    var seqId   int
    var reply   *icmpMessage
    var icmpPdu []byte
    var read    int
    var ipVer   byte
    var err     error

    for {
        read, err = conn.Read(icmpBuffer)
        if err != nil { break }
        ipVer = icmpBuffer[0]>>4

        if ipVer == 4 {
            if read < 28 { continue }
            // ipHeader = icmpBuffer[0:20]
            icmpPdu = icmpBuffer[20:read]
        } else if ipVer == 6 {
            // TODO support v6
            // if read < 48 { continue }
            // icmpPdu = icmpBuffer[40:read]
            continue
        } else {
            continue
        }

        reply, err = parseICMPMessage(icmpPdu)
        if err != nil { continue }
        if reply.Type == icmpv4EchoRequest { continue }
        if reply.Type == icmpv6EchoRequest { continue }

        body := reply.Body
        if body.GetProcID() != procId { continue }

        seqId = body.GetSequenceID()
        eventchan <- ppingEvent{From: "fromReceiver", SeqId: seqId}
        counter -= 1
        if counter == 0 { break }
    }
}

func computeComplementSum(bytes []byte) uint32 {
    checksumLen := len(bytes) - 1
    sum := uint32(0)
    for i := 0; i < checksumLen; i+=2 {
        sum += uint32(bytes[i+1])<<8 | uint32(bytes[i])
    }

    if checksumLen&1 == 0 { sum += uint32(bytes[checksumLen]) }

    sum = sum>>16 + sum&0xffff
    sum = sum + sum>>16
    return sum
}






/* ICMP PART */
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
    Encode()        ([]byte, error)
    GetProcID()     int
    GetSequenceID() int
}

func (m *icmpMessage) Encode(conn net.Conn) ([]byte, error) {
    var bytes []byte
    if m.Type == icmpv4EchoRequest {
        bytes = []byte{byte(m.Type), byte(m.Code), 0, 0}
        if m.Body != nil && m.Body.Len() != 0 {
            mb, err := m.Body.Encode()
            if err != nil { return nil, err }
            bytes = append(bytes, mb...)
        }
        s := computeComplementSum(bytes)

        // Place checksum back in header; using ^= avoids the
        // assumption the checksum bytes are zero.
        bytes[2] ^= byte(^s & 0xff)
        bytes[3] ^= byte(^s >> 8)
    } else if m.Type == icmpv6EchoRequest {
        // TODO build v6 pseudo header, add body and computeComplementSum
        // use conn to get src/dst address
    }
    return bytes, nil
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

// parseICMPEcho parses b as an ICMP echo request or reply message body.
func parseICMPEcho(b []byte) (*icmpBody, error) {
    bodylen := len(b)
    p := &icmpBody{
        ID:  int(b[0])<<8 | int(b[1]),
        Seq: int(b[2])<<8 | int(b[3]) }
    if bodylen > 4 {
        p.Data = make([]byte, bodylen-4)
        copy(p.Data, b[4:])
    }
    return p, nil
}









// imcpBody represenets an ICMP echo request or reply message body.
type icmpBody struct {
    ID   int    // identifier
    Seq  int    // sequence number
    Data []byte // data
}

func (p *icmpBody) GetProcID()      int { return p.ID }
func (p *icmpBody) GetSequenceID()  int { return p.Seq }
func (p *icmpBody) Len() int {
    if p == nil { return 0 }
    return 4 + len(p.Data)
}
func (p *icmpBody) Encode()         ([]byte, error) {
    // Encode returns the binary enconding of the ICMP echo request or
    // reply message body p.
    b := make([]byte, 4+len(p.Data))
    b[0], b[1] = byte(p.ID>>8), byte(p.ID&0xff)
    b[2], b[3] = byte(p.Seq>>8), byte(p.Seq&0xff)
    copy(b[4:], p.Data)
    return b, nil
}





/* 
FLAGS PART:
TODO flags
    -w
    -c
    -s
    -n
    -i
    -l
*/
var VersionFlag     bool
var HostFlag        string
var SourceFlag      string
var NumberFlag      int
var IntervalFlag    int
var TtlFlag         int
var TimeoutFlag     int
var SizeFlag        int
var Ip6Flag         bool

func init() {
    flag.BoolVar(&VersionFlag,  "version",  false, "Show version")
    flag.StringVar(&HostFlag,   "host",     "", "Target")
    flag.IntVar(&TimeoutFlag,   "timeout",  5000, "Timeout")
    flag.StringVar(&SourceFlag, "source",   "", "From host or ip")
    flag.IntVar(&NumberFlag,    "number",   5, "Number of packets to send")
    flag.IntVar(&IntervalFlag,  "interval", 100, "Send packet interval in millisecond")
    flag.IntVar(&TtlFlag,       "ttl",      0, "TTL on outgoing packets")
    flag.IntVar(&SizeFlag,      "size",     56,"Size of the icmp body in octets")
    flag.BoolVar(&Ip6Flag,      "ipv6",     false, "Enable version 6 icmp")
}

func parseFlags() {
    flag.Parse()

    if VersionFlag == true {
        printVersion()
        os.Exit(0)
    } else if HostFlag == "" { // MINIMUM MANDATORY
        flag.PrintDefaults()
        os.Exit(2)
    }
}

func printVersion() { fmt.Printf("go_check_icmp V0.1\n") }
