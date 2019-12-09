package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/*
The purpose of this program is to perform flow analysis on incoming packets sent from the SDN

* All incoming packets are assumed to be analysed (ie. no sorting needs to occur)
*/

type PacketSignature struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

type PacketData struct {
	Timestamp time.Time
	Signature PacketSignature
	Length    uint32
	TCPSyn    bool
	TCPAck    bool
	TCPFin    bool
}

type FlowEntry struct {
	Key       PacketSignature
	CreatedTS time.Time
	UpdatedTS time.Time

	Prev *FlowEntry
	Next *FlowEntry

	// Counters
	Bytes       uint32
	PacketCount uint32
}

// This is the hash map that stores the flow data
type ExpiryMap struct {
	Map     map[PacketSignature]*FlowEntry
	Latest  *FlowEntry
	Oldest  *FlowEntry
	Timeout time.Duration

	// Counters
	NEntries uint
	NExpired uint

	Mutex sync.Mutex
}

var IPFlowExpiryMap ExpiryMap
var i int

func initIPFlowAnalysisFlowFunction() packetFlowFunction {
	fmt.Println("!! IPFlowAnalysis flow function...")
	i = 0

	timeoutDuration := "5s"
	fmt.Println("# Creating ExpiryMap with a timeout of", timeoutDuration)
	IPFlowExpiryMap.Map = make(map[PacketSignature]*FlowEntry)
	IPFlowExpiryMap.Latest = nil
	IPFlowExpiryMap.Oldest = nil
	IPFlowExpiryMap.Timeout, _ = time.ParseDuration(timeoutDuration)
	IPFlowExpiryMap.NEntries = 0
	IPFlowExpiryMap.NExpired = 0

	go func() {
		for {
			updateOldest()
		}
	}()

	return packetFlowFunction(IPFlowAnalysisFlowFunction)
}

func IPFlowAnalysisFlowFunction(packet gopacket.Packet) {
	// ! this following code shouldn't exist here and should be done elsewhere - pressed for time

	// Store the data in packetData struct
	var packetData PacketData
	packetData.Length, packetData.Timestamp = uint32(packet.Metadata().Length), packet.Metadata().Timestamp

	// Decode for IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ipData, _ := ipLayer.(*layers.IPv4)

		packetData.Signature.SrcIP = ip2int(ipData.SrcIP)
		packetData.Signature.DstIP = ip2int(ipData.DstIP)
	} else {
		// ignore non-ip layers
		return
	}

	// Decode for TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcpData, _ := tcpLayer.(*layers.TCP)

		packetData.Signature.SrcPort = uint16(tcpData.SrcPort)
		packetData.Signature.DstPort = uint16(tcpData.DstPort)
		packetData.TCPSyn = tcpData.SYN
		packetData.TCPAck = tcpData.ACK
		packetData.TCPFin = tcpData.FIN
	}

	// Decode for UDP layer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udpData, _ := udpLayer.(*layers.UDP)

		packetData.Signature.SrcPort = uint16(udpData.SrcPort)
		packetData.Signature.DstPort = uint16(udpData.DstPort)
	}

	IPFlowExpiryMap.Mutex.Lock()
	// Check if an exist flow has been inserted
	flowEntry, exists := IPFlowExpiryMap.Map[packetData.Signature]
	if exists != true {
		var newEntry FlowEntry
		newEntry.Key = packetData.Signature
		newEntry.CreatedTS = time.Now() // not using time sigs -> not compadible with pcaps
		newEntry.UpdatedTS = time.Now()
		newEntry.Bytes = packetData.Length
		newEntry.PacketCount = 1

		flowEntry = &newEntry

		// insert into hashmap
		IPFlowExpiryMap.Map[flowEntry.Key] = flowEntry
	} else {
		flowEntry.UpdatedTS = time.Now()
		flowEntry.Bytes += packetData.Length
		flowEntry.PacketCount++
	}

	updateToLatestFlowEntryInExpiryMap(flowEntry)
	IPFlowExpiryMap.Mutex.Unlock()
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func updateToLatestFlowEntryInExpiryMap(entry *FlowEntry) {
	// if already latest, do nothing
	if entry == IPFlowExpiryMap.Latest {
		return
	}

	// if already noted in the entry, remove from the chain and rejoin previous and next together
	// check for nils
	if entry.Prev != nil {
		entry.Prev.Next = entry.Next
	}

	if entry.Next != nil {
		entry.Next.Prev = entry.Prev
	}

	// Is this currently set to be the oldest
	if entry == IPFlowExpiryMap.Oldest {
		IPFlowExpiryMap.Oldest = entry.Next
	}

	// Make entry's next and prev point to nil
	entry.Next = nil
	entry.Prev = nil

	// Update to become latest
	if IPFlowExpiryMap.Latest == nil {
		IPFlowExpiryMap.Latest = entry
		IPFlowExpiryMap.Oldest = entry
	} else {
		IPFlowExpiryMap.Latest.Next = entry
		entry.Prev = IPFlowExpiryMap.Latest
		IPFlowExpiryMap.Latest = entry

		if IPFlowExpiryMap.Oldest == nil {
			IPFlowExpiryMap.Oldest = IPFlowExpiryMap.Latest
		}
	}

	IPFlowExpiryMap.NEntries++
}

func updateOldestFlowEntryInExpiryMap() *FlowEntry {
	oldEntry := IPFlowExpiryMap.Oldest

	IPFlowExpiryMap.Oldest = IPFlowExpiryMap.Oldest.Next

	if IPFlowExpiryMap.Oldest != nil {
		IPFlowExpiryMap.Oldest.Prev = nil
	}

	IPFlowExpiryMap.NExpired++

	return oldEntry
}

func updateOldest() {
	if IPFlowExpiryMap.Oldest != nil {
		// If the time difference between now and the oldest flow entry is greater than the
		// timeout duration - Clean: remove from the map and record data
		if time.Now().Sub(IPFlowExpiryMap.Oldest.UpdatedTS) > IPFlowExpiryMap.Timeout {
			expiredEntry := updateOldestFlowEntryInExpiryMap()

			fmt.Println("********* FLOW ATTRIBUTES ********")
			fmt.Print("SrcIP: " + int2ip(expiredEntry.Key.SrcIP).String() + " (" + strconv.FormatInt(int64(expiredEntry.Key.SrcPort), 10) + ") ")
			fmt.Println("--> DstIP: " + int2ip(expiredEntry.Key.DstIP).String() + " (" + strconv.FormatInt(int64(expiredEntry.Key.DstPort), 10) + ") ")
			fmt.Println("Total Number of Packets: " + strconv.FormatInt(int64(expiredEntry.PacketCount), 10))
			fmt.Println("Total Bytes Sent: " + strconv.FormatInt(int64(expiredEntry.Bytes), 10))
			averageBytesPerPacket := expiredEntry.Bytes / expiredEntry.PacketCount
			fmt.Println("Average number of Bytes per Packet: " + strconv.FormatInt(int64(averageBytesPerPacket), 10) + " Bytes")
			durationOfFlow := expiredEntry.UpdatedTS.Sub(expiredEntry.CreatedTS)
			fmt.Println("Total Duration for flow: " + durationOfFlow.String())

			IPFlowExpiryMap.Mutex.Lock()
			delete(IPFlowExpiryMap.Map, expiredEntry.Key)
			IPFlowExpiryMap.Mutex.Unlock()
		}
	}
}
