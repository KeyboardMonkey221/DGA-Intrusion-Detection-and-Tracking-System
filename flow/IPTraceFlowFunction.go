package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type IPTracingPcapFile struct {
	pcapFile      *os.File
	pcapWriter    *pcapgo.NgWriter
	mutex         sync.Mutex
	numOfCaptures int
	targetIPAddr  string
}

// IPTraceHashmap contains a hash map of the IPs that are being traced
// In addition, it stores the number of packets coming through
var IPTraceHashmap map[string]*IPTracingPcapFile

func initIPTraceFlowFunction() packetFlowFunction {
	fmt.Println("# Initialising flow function IPTrace")
	IPTraceHashmap = make(map[string]*IPTracingPcapFile)

	fmt.Println("FlowFunction IPTraceFlowFunction intialised")
	return packetFlowFunction(IPTraceFlowFunction)
}

func IPTraceFlowFunction(packet gopacket.Packet) {
	// 1. Packet Checking
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}

	// 2. Packet Action
	ipData, _ := ipLayer.(*layers.IPv4)

	// Check if either the src or dest IP is the hashmap
	srcIPString := ipData.SrcIP.String()
	dstIPString := ipData.DstIP.String()
	srcIPTraceStruct, okSrc := IPTraceHashmap[srcIPString]
	destIPTraceStruct, okDest := IPTraceHashmap[dstIPString]

	var IPTraceStruct *IPTracingPcapFile
	if okSrc {
		IPTraceStruct = srcIPTraceStruct
	} else if okDest {
		IPTraceStruct = destIPTraceStruct
	} else {
		// ignore - not to be traced
		return
	}

	// Create worker to write packet to file
	globalWaitGroup.Add(1)
	go func() {
		IPTraceStruct.mutex.Lock()
		err := IPTraceStruct.pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		if err != nil {
			fmt.Println(err)
		}
		IPTraceStruct.numOfCaptures++

		IPTraceStruct.mutex.Unlock()

		globalWaitGroup.Done()
	}()

}

func addIPToTrace(ipAddress string) {
	// Check if already exists, if not, initialize the IPTracingPcapFile struct
	_, ok := IPTraceHashmap[ipAddress]
	if ok == false {
		fmt.Println("Adding: ", ipAddress, "to hashmap")
		var myStruct IPTracingPcapFile
		var err error
		myStruct.pcapFile, err = os.Create("dataCaptured/Trace|" + ipAddress + "|.pcap")
		if err != nil {
			log.Fatal(err)
		}

		myStruct.pcapWriter, err = pcapgo.NewNgWriter(myStruct.pcapFile, layers.LinkTypeEthernet)
		if err != nil {
			log.Fatal(err)
		}

		myStruct.numOfCaptures = 0

		myStruct.targetIPAddr = ipAddress

		// insert into hashmap
		IPTraceHashmap[ipAddress] = &myStruct
	}
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func flushWriters() {
	for _, value := range IPTraceHashmap {
		value.pcapWriter.Flush()
	}
}
