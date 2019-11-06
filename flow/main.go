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
var clientMACAddress string
var networkDeviceInterfaceName string
var incomingPacketChannelSize int
var globalWaitGroup sync.WaitGroup

func init() {
	flag.StringVar(&pcapFilePath, "f", "no.pcap", "For offline parsing, provide filepath to .pcap file to be parsed")
	flag.StringVar(&clientMACAddress, "MAC", "", "For offline parsing, provide the Client MAC address to distinguish client->server flow")
	flag.StringVar(&networkDeviceInterfaceName, "i", "no.interface", "For online parsing (has priority over offline), provide the Network Device Interface's name")

	incomingPacketChannelSize = 10000
}

func main() {
	flag.Parse()

	fmt.Println("########### INITIATING ############")

	fmt.Println("** Opening the pcap handle...")
	// Handle that acts as the connection to the source of pcap data
	var pcapHandle *pcap.Handle = getpcapHandle()
	defer pcapHandle.Close()
	fmt.Println("Opening the pcap handle was successful!")

	// Before the parsing of packets begins, add starting flow functions the slice of packetFlowFunctions
	fmt.Println("** Intialising starting flow functions...")
	addFlowFunction(initDGALookupOnDNSResponsesFlowFunction())
	addFlowFunction(initIPTraceFlowFunction())

	fmt.Println("** Initiating packet flow from pcap handle...")
	// Get the channel with packets
	incomingPacketChannel := getPacketsChannelFromHandle(pcapHandle)

	counter := 0
	var totalTimeTaken time.Duration = 0
	for packet := range incomingPacketChannel {
		if counter%100 == 0 {
			fmt.Println("Heartbeat: Parsed 100 packets...")
		}

		startTime := time.Now()
		for _, flowFunction := range packetFlowFunctions {
			flowFunction(packet)
		}
		totalTimeTaken += time.Now().Sub(startTime)
		counter++
	}

	fmt.Println("Main thread waiting...")
	globalWaitGroup.Wait()

	fmt.Println("Flushing writers...")
	flushWriters()

	fmt.Println("***FINISHED***")
	fmt.Println("Number of packets parsed: ", counter)
	fmt.Println("TotalTimeTaken: ", totalTimeTaken)
	average := totalTimeTaken.Seconds() / float64(counter)
	fmt.Printf("Therefore, average time spent on each packet: %.10f seconds\n", average)
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