package main

import (
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/nats-io/go-nats"
)

const dnsSubject = "dns_packets"

/*
Creates a go routine that parses NATS messages from the configured NATSUrl,
decodes them and then parses them into the DNSPacketChannel
*/
func startDNSPacketListenerForNATSMessages() {
	nc, err := nats.Connect(conf.Nats.NatsURL)
	if err != nil {
		fmt.Println(err)
		panic("Error connecting to NATS Server")
	}

	_, _ = nc.Subscribe(dnsSubject, func(msg *nats.Msg) {
		packetBundle := DnsPacketBundle{}
		err = proto.Unmarshal(msg.Data, &packetBundle)
		if err != nil {
			fmt.Println("Error decoding protobuf", err)
		}
		fmt.Println("Received packet attributes for", len(packetBundle.Packets), "DNS Packets")
		for _, packet := range packetBundle.Packets {
			DNSPacketChannelFromNATS <- *packet
		}
	})

	nc.Flush()
}
