package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Sets up the context before a flowFunction
// Must return a flow function that will perform the checks required on incoming packets
// and look to delegate work accordingly
func initDGALookupFlowFunction() packetFlowFunction {
	// initialize the DGA database for lookups
	initDGADatabase()

	return packetFlowFunction(DGALookupFlowFunction)
}

/* DGALookupFlowFunction
Designed to look for DNS layers and check whether the domain
name is present in the in-memory database

If found, then the function will create add a new flow function to trace the ip conversation
and create a new channel as well for the new flow function to direct packets too
*/
func DGALookupFlowFunction(packet gopacket.Packet) {
	// Decode the layers and extract important data

	// Check if the packet contains a DNS layer
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {
		fmt.Println("DNS layer detected")
		dnsPacket, _ := dnsLayer.(*layers.DNS)

		fmt.Println("DNS transaction id:", dnsPacket.ID)
		fmt.Println("Printing queries...")
		for _, query := range dnsPacket.Questions {
			fmt.Println(query.Name)
		}

		fmt.Println("Printing answers...")
		for _, answer := range dnsPacket.Answers {
			fmt.Println(answer.Name)
		}
	}

}
