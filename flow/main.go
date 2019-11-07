package main

import (
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var pcapFilePath string
var NATSSwitch string
var networkDeviceInterfaceName string
var incomingPacketChannelSize int
var mainThreadWaitGroup sync.WaitGroup
var conf FlowConfig
var DNSPacketChannelFromNATS chan DnsPacket
var packetChannelFromPcapHandle chan gopacket.Packet

func init() {
	flag.StringVar(&pcapFilePath, "f", "no.pcap", "For offline parsing, provide filepath to .pcap file to be parsed")
	flag.StringVar(&networkDeviceInterfaceName, "i", "no.interface", "Declare an network interface for online parsing")
	flag.StringVar(&NATSSwitch, "NATS", "off", "Provide 'on' to indicate that packets are to be received from NATS")
	flag.String("config", "flow.toml", "Configuration file")

	initRedisDB()
}

func main() {
	flag.Parse()
	conf = GetConfig()
	fmt.Println("########### INITIATING FLOW ############")

	/*
		Determine whether we're sourcing DNS packets from a pcap file or from the NATS server

		If DNS packets are coming from NATS, initiate channel to collect NATS packets and the workers too
	*/
	if NATSSwitch == "on" {
		fmt.Println("!! DNS PacketSource: NATS")
		DNSPacketChannelFromNATS = make(chan DnsPacket, 10000)

		// Producers
		fmt.Println("** Initialising DNS Packet NATS Listener...")
		go startDNSPacketListenerForNATSMessages()

		// Consumers - will perform DGA lookups
		fmt.Println("* Created worker...")
		go func() {
			for p := range DNSPacketChannelFromNATS {
				fmt.Println(p)
			}
		}()
	} else {
		fmt.Println("!! DNS PacketSource offline ")

		// Add the flowFunction to parse for DNS Responses and perform DGA lookups
		addFlowFunction(initDGALookupOnDNSResponsesFlowFunction())
	}

	fmt.Print("!! Opening the pcap handle...")
	var pcapHandle *pcap.Handle = getpcapHandle()
	defer pcapHandle.Close()
	fmt.Println("Success")

	fmt.Print("** Initialising packet flow from pcap handle...")
	packetChannelFromPcapHandle = getPacketsChannelFromHandle(pcapHandle)
	fmt.Println("Success")

	fmt.Println("!! Adding flow functions to parse packets from pcapHandle...")
	addFlowFunction(initIPTraceFlowFunction())
	fmt.Println("@@ Finished")

	fmt.Println("* Create worker...")
	func() {
		// Stats for recording average time spent on each packet
		packetCounter := 1
		timer := time.Now()

		for packet := range packetChannelFromPcapHandle {
			if packetCounter%1000000 == 0 {
				fmt.Println("Heartbeat: Parsed 1 000 000 packets...")

				timeTakenForPackets := time.Now().Sub(timer)
				averageForMillionPackets := timeTakenForPackets.Seconds() / float64(1000000)

				fmt.Println("Took: ", timeTakenForPackets)
				fmt.Printf("Average time per packet: %.10f seconds\n", averageForMillionPackets)

				timer = time.Now()
			}

			/*
				Execute each flow function on packet
				Flow functions will perform a check and on success perform an action
			*/
			for _, flowFunction := range packetFlowFunctions {
				flowFunction(packet)
			}

			packetCounter++
		}
	}()

	fmt.Println("Main thread waiting...")
	mainThreadWaitGroup.Wait()

	fmt.Println("Flushing writers...")
	flushWriters()

	fmt.Println("***FINISHED***")
}

// Depending on the command-line arguments provided by the user,
// either return a *pcap.handle for online or offline parsing
func getpcapHandle() *pcap.Handle {
	var myHandle *pcap.Handle = nil
	var err error

	if networkDeviceInterfaceName != "no.interface" {
		fmt.Println("** Network Interface:", pcapFilePath)
		myHandle, err = pcap.OpenLive(networkDeviceInterfaceName, 262144, true, pcap.BlockForever)
	} else if pcapFilePath != "no.pcap" {
		fmt.Println("** Pcap file:", pcapFilePath)
		myHandle, err = pcap.OpenOffline(pcapFilePath)
	} else {
		log.Fatal("Please provide an interface or pcap file")
	}

	// Before returning handle, check for errors
	if err != nil {
		log.Fatal("Error creating Packet Handle: ", err)
	}

	return myHandle
}

func getPacketsChannelFromHandle(handle *pcap.Handle) chan gopacket.Packet {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Set NoCopy on - don't make copies of the Packets (speed)
	fmt.Println("* Decoding option NoCopy: true")
	packetSource.DecodeOptions.NoCopy = true

	// Set Lazy off - load all layers (could not be needed)
	fmt.Println("* Decoding option Lazy: false")
	packetSource.DecodeOptions.Lazy = false

	// Return the channel to the packet stream
	return packetSource.Packets()
}
