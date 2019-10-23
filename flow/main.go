package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var pcapFilePath string
var clientMACAddress string
var networkDeviceInterfaceName string

func init() {
	flag.StringVar(&pcapFilePath, "f", "no.pcap", "For offline parsing, provide filepath to .pcap file to be parsed")
	flag.StringVar(&clientMACAddress, "MAC", "", "For offline parsing, provide the Client MAC address to distinguish client->server flow")
	flag.StringVar(&networkDeviceInterfaceName, "i", "no.interface", "For online parsing (has priority over offline), provide the Network Device Interface's name")
}

func main() {
	flag.Parse()

	// Handle that acts as the connection to the source of pcap data
	var pcapHandle *pcap.Handle = getpcapHandle()
	defer pcapHandle.Close()

	// Create a channel that packet data will be asynchronously parsed into from the handle
	var incomingPacketChannel chan gopacket.Packet
	incomingPacketChannel = getPacketsChannelFromHandle(pcapHandle)

	// Before the parsing of packets begins, add starting flow functions the slice of packetFlowFunctions
	addFlowFunction(initDGALookupFlowFunction())

	// Create workers to parse, read, and direct packet traffic
	// Option to create multiple workers
	for i := 0; i < 1; i++ {
		fmt.Println("initialise parser worker...")
		go parsePacketsWorker(incomingPacketChannel)
	}

	// Blocking call - on a later date, should convert into a wait group
	fmt.Scanln()
}

// Depending on the command-line arguments provided by the user,
// either return a *pcap.handle for online or offline parsing
func getpcapHandle() *pcap.Handle {
	var myHandle *pcap.Handle = nil
	var err error

	if networkDeviceInterfaceName != "no.interface" {
		fmt.Println("Online parsing initiating...")

	} else if pcapFilePath != "no.pcap" {
		fmt.Println("Offline parsing initiating...")
		fmt.Println("Reading from:", pcapFilePath)

		// Open pcap file
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

	// Set NoCopy on - don't make copies of the Packets
	// For speed as we don't want to alter the underlying copy
	packetSource.DecodeOptions.NoCopy = true

	// Set Lazy off - load all layers (could not be needed)
	packetSource.DecodeOptions.Lazy = false

	// Return the channel to the packet stream
	return packetSource.Packets()
}
