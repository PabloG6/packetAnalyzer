package main

import (
	"bufio"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"log"
	"net/http"
	"time"
)

type httpStreamFactory struct {
}

type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (streamFactory *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	stream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}

	go stream.run()
	return &stream.r
}
func (stream *httpStream) run() {
	log.Println("reading request stream: ")
	buf := bufio.NewReader(&stream.r)
	for {
		req, err := http.ReadRequest(buf)
		if err != io.EOF {
			return
		} else if err != nil {
			log.Println("Error reading stream: ", stream.net, stream.transport, err)
		} else {
			bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
			req.Body.Close()

			log.Println("Received request from stream", stream.net, stream.transport, ":", req, "with", bodyBytes, "bytes in request body")

		}
	}
}
func main() {
	var handle *pcap.Handle
	var err error
	handle, err = pcap.OpenLive("lo0", int32(128), true, pcap.BlockForever)

	if err != nil {
		log.Fatal(err.Error())
	}

	err = handle.SetBPFFilter("src port 300 or dst port 3000")

	if err != nil {
		log.Fatal("bpfFilter: ", err.Error())
	}
	//set up assembly
	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	ticker := time.Tick(time.Second * 10)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	log.Println("packet channel: ", packets)
	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			log.Println("packet: ", packet)
			if packet == nil {
				return
			}

			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Second * -20))
			log.Println("flushing lol")
		}
	}
}
