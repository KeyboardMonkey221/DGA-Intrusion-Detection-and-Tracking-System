package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// * FlowFunction generic type
type packetFlowFunction func(gopacket.Packet)

// * Channel
var packetChannelFromPcapHandle chan gopacket.Packet

// * Storage for flow functions
// ? implement a tree-like structure for storing flow functions
var packetFlowFunctions [](packetFlowFunction)

// Given a channel of gopacket.Packet, apply various functions that will parse packets
// into channels (up to them where and in what form)
// All functions should take COPIES of the packet, never the source (other functions may need it)
// Intended to be used in multiple goroutines (as a worker)
// ! not in use
// TODO to be fixed - low priority at the moment
func parsePacketsWorker(incomingPackets <-chan gopacket.Packet) {
	for packet := range incomingPackets {
		// attempt all the flow functions
		for _, flowFunction := range packetFlowFunctions {
			// see below for notes **
			flowFunction(packet)
		}
	}
}

// Add a flowFunction to the beginning of the flowFunctions Slice
func addFlowFunction(flowFunction func(gopacket.Packet)) {
	// Simple now, but could be a tree insert later on

	// Need to use a custom type to store function pointers (defined above)
	var newFlowFunction packetFlowFunction = flowFunction

	// Append newFunction to the end of the slice
	packetFlowFunctions = append(packetFlowFunctions, newFlowFunction)
}

func initialiseChannelsForNetworkInterfaceOrPcap() {
	// Check if a network interface or pcap file has been provide
	if networkDeviceInterfaceName == "no.interface" && pcapFilePath == "no.pcap" {
		fmt.Println(" ## No interface or pcap provided - FlowFunctions: OFFLINE")
		return
	}

	// Create a handle on either the provided pcap file or network interface
	// ? currently does not support dual parsing of packets from pcap and interface
	var pcapHandle *pcap.Handle
	var err error
	if networkDeviceInterfaceName != "no.interface" {
		fmt.Println("## FlowFunctions: Network Interface selected", pcapFilePath)
		pcapHandle, err = pcap.OpenLive(networkDeviceInterfaceName, 262144, true, pcap.BlockForever)
	} else {
		fmt.Println("## FlowFunctions: pcapFile selected", pcapFilePath)
		pcapHandle, err = pcap.OpenOffline(pcapFilePath)
	}

	if err != nil {
		log.Fatal("FlowFunction: Error handling interface: ", err)
	}

	// Declare a packetSource from the pcapHandle
	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())

	// * Set configurations for packets to be parsed into the channel
	// Don't pass around packet copies - parse the pointer to original (faster)
	packetSource.DecodeOptions.NoCopy = true
	// Load all layers - apparently may make errors if not handled correctly
	packetSource.DecodeOptions.Lazy = false

	// * gopackets are being filled into channel from source
	packetChannelFromPcapHandle = packetSource.Packets()

	// * Initialise FlowFunctions
	fmt.Println("Initialising flowFunctions")
	// eg addFlowFunction(initIPTraceFlowFunction())

	fmt.Println("* Create worker for flow functions")
	func() {
		mainThreadWaitGroup.Add(1)

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
}
