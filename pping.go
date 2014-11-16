package main

import "fmt"
import "flag"
import "bytes"
import "errors"
import "net"
import "os"
import "time"
import "strings"

type ppingEvent struct {
    From    string
    SeqId   int
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
var Ip6IfFlag       string

var LocalAddr       string
var RemoteAddr      string

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
    flag.StringVar(&Ip6IfFlag,  "ipv6-if",  "", "Required if host is an ipv6 link-local address")
}

func main() {
    parseFlags()
    //timeout  := time.Duration(TimeoutFlag)  * time.Millisecond
    interval := time.Duration(IntervalFlag) * time.Millisecond

    fmt.Println(strings.Join([]string{HostFlag, Ip6IfFlag}, "%"))
    var err         error
    var conn        net.Conn
    var ipVersion   int
    var host        string

    if Ip6Flag == true {
        ipVersion   = 6
        if Ip6IfFlag != "" {
            host = strings.Join([]string{HostFlag,Ip6IfFlag}, "%") 
        } else {
            host = HostFlag
        }
        conn, err   = net.Dial("ip6:58", host)
    } else {
        ipVersion   = 4
        host = HostFlag
        conn, err   = net.Dial("ip4:1", host)
    }
    if err != nil { fmt.Println(err); os.Exit(1) }
    LocalAddr   = conn.LocalAddr().String()
    RemoteAddr  = conn.RemoteAddr().String()

    procId := os.Getpid()&0xffff

    var eventchan chan ppingEvent = make(chan ppingEvent)
    go icmpEchoReceiver(conn,eventchan,ipVersion,procId)
    go icmpEchoSender(conn,eventchan,ipVersion,procId,interval)

    var counter int = NumberFlag
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
    fmt.Println("ok")
}

func icmpEchoSender(
    conn        net.Conn,
    eventchan   chan ppingEvent,
    ipVersion   int,
    procId      int,
    interval    time.Duration) {
    var err error

    var requestCode int
    if ipVersion == 4 {
        requestCode = icmpv4EchoRequest
    } else if ipVersion == 6 {
        requestCode = icmpv6EchoRequest
    }
    for i := 0; i < NumberFlag; i++ {
        seqId := i + 1
        pdu, _ := (&icmpMessage{
            Type: requestCode,
            Code: 0,
            Body: &icmpBody{
                ID:     procId,
                Seq:    seqId,
                Data:   bytes.Repeat([]byte("g"), SizeFlag),
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
        ipVersion   int,
        procId      int) {

    icmpBuffer := make([]byte, icmpPacketMaxSize)

    var seqId   int
    var reply   *icmpMessage
    var icmpPdu []byte
    var read    int
    var ip4Ver   byte
    var err     error
    var counter int = NumberFlag

    // WTF
    // for an unknown reason, conn.Read on version 6 skipp the v6
    // header.
    if ipVersion == 6 {
        for 
        {
            read, err = conn.Read(icmpBuffer)

            if icmpBuffer[0] != byte(icmpv6EchoReply) {
                continue
            }

            reply, err = parseICMPMessage(icmpBuffer)
            // TODO validate checksum
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
    } else if ipVersion == 4 {
        for {
            read, err = conn.Read(icmpBuffer)
            if err != nil { break }

            ip4Ver = icmpBuffer[0]>>4
            if ip4Ver != 4 {
                continue
            }
            icmpPdu = icmpBuffer[20:read]

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

func (msg *icmpMessage) Encode(conn net.Conn) ([]byte, error) {
    var pdu []byte
    if msg.Type == icmpv4EchoRequest {
        pdu = []byte{byte(msg.Type), byte(msg.Code), 0, 0}
        if msg.Body != nil && msg.Body.Len() != 0 {
            messageBody, err := msg.Body.Encode()
            if err != nil { return nil, err }
            pdu = append(pdu, messageBody...)
        }
        s := computeComplementSum(pdu)

        // Place checksum back in header; using ^= avoids the
        // assumption the checksum pdu are zero.
        pdu[2] ^= byte(^s & 0xff)
        pdu[3] ^= byte(^s >> 8)
    } else if msg.Type == icmpv6EchoRequest {
        // build icmp pdu in pdu var
        pdu = []byte{byte(msg.Type), byte(msg.Code), 0, 0}
        if msg.Body != nil && msg.Body.Len() != 0 {
            messageBody, err := msg.Body.Encode()
            if err != nil { return nil, err }
            pdu = append(pdu, messageBody...)
        }

        // BUILD PSEUDO HEADER
        var pseudoHeader []byte
        // append source and dest address
        var localAdd     []byte
        var remoteAdd    []byte
        localAdd    = net.ParseIP(LocalAddr)
        remoteAdd   = net.ParseIP(RemoteAddr)
        pseudoHeader = append(localAdd, remoteAdd...)
        // append ICMPv6 len of pdu
        // !!WTF how can this work when only specifying the last byte?
        pduLenHead := []byte{0,0,0,byte(len(pdu))}
        pseudoHeader = append(pseudoHeader, pduLenHead...)
        // append Zero and Next header(58) field
        var lastHeaderField []byte
        lastHeaderField = []byte{0,0,0,58}
        pseudoHeader = append(pseudoHeader, lastHeaderField...)
        // append icmp packet
        pseudoHeader = append(pseudoHeader, pdu...)
        // compute checksum
        s := computeComplementSum(pseudoHeader)
   
        // Place checksum in pdu
        pdu[2] ^= byte(^s & 0xff)
        pdu[3] ^= byte(^s >> 8)
    }
    return pdu, nil
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
