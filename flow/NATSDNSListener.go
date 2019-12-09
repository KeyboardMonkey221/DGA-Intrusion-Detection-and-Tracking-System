package main

import (
	"fmt"

	"github.com/go-redis/redis"
	"github.com/golang/protobuf/proto"
	"github.com/nats-io/go-nats"
)

const dnsSubject = "dns_packets"

// * Channels handling Packet data
// ? Future development: Could be receiving different NATS messages of different types
// ? Hence, should be a hashmap of type, channel type
var DNSPacketChannelFromNATS chan DnsPacket

/*
Creates a go routine that parses NATS messages from the configured NATSUrl,
decodes them and then parses them into the DNSPacketChannel
*/
func startDNSPacketListenerForNATSMessages() {
	nc, err := nats.Connect(NATSconfig.Nats.NatsURL)
	if err != nil {
		fmt.Println(err)
		panic("Error connecting to NATS Server")
	}

	fmt.Println("* Attempt to subscribe to NATs...")
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

func initialiseChannelsForNATS() {
	fmt.Println("# NATS packet flow set to be: ", NATSSwitch)
	if NATSSwitch == "on" {
		DNSPacketChannelFromNATS = make(chan DnsPacket, 10000)

		fmt.Println("* Initialising DNS Packet NATS Listener...")
		go startDNSPacketListenerForNATSMessages()

		fmt.Println("* Created worker for NATS...")
		go func() {
			mainThreadWaitGroup.Add(1)

			for DNSPacket := range DNSPacketChannelFromNATS {
				DNSPacketInfo := DNSPacket.GetDnsInfo()

				// Only focus on DNS packets with answers (responses)
				answersRecords := DNSPacketInfo.Answers
				if len(answersRecords) != 0 {
					// iterating with range didn't work
					for i := 0; i < len(answersRecords); i++ {
						// Extract the domain name from the record
						domainName := string(answersRecords[i].GetName())
						TTL := int(answersRecords[i].Ttl)

						// Perform a DNS lookup
						// ? A NATS based lookup could be faster than redis
						returnVal := DGARedisClient.Get(domainName)

						if returnVal.Err() != redis.Nil {
							commandCentreIP := string(answersRecords[i].GetByteData())
							fmt.Println("Malware Found: ", domainName)
							fmt.Println("-> ", commandCentreIP)

							// Should be a go routine as we don't want to wait for a response
							go sendPOSTRequestToSDNController(commandCentreIP, commandCentreIP, TTL)

							writeToCSV(domainName, DNSPacket.GetDstIp(), "Yes", string(answersRecords[i].GetByteData()))
						} else {
							writeToCSV(domainName, DNSPacket.GetDstIp(), "No", "")
						}
					}
				}
			}
		}()
	}
}
