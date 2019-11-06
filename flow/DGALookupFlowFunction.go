package main

import (
	"fmt"

<<<<<<< HEAD
	"github.com/go-redis/redis"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hashicorp/go-memdb"
)

// Create a variable to store a readtransaction pointer to query the db
var readTransaction *memdb.Txn

// Sets up the context before a flowFunction
// Must return a flow function that will perform the checks required on incoming packets
// and look to delegate work accordingly
func initDGALookupOnDNSResponsesFlowFunction() packetFlowFunction {
	fmt.Println("# Initialising flow function DGALookup")

	// initialize the DGA database for lookups
	initRedisDB()

	fmt.Println("FlowFunction DGALookupFlowFunction intialised")
	return packetFlowFunction(DGALookupOnDNSResponsesFlowFunction)
}

/* DGALookupOnDNSQueriesFlowFunction
=======
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
>>>>>>> 2f758f6ac37b6ecf3a9ac9647b4cc9910f45c5ad
Designed to look for DNS layers and check whether the domain
name is present in the in-memory database

If found, then the function will create add a new flow function to trace the ip conversation
and create a new channel as well for the new flow function to direct packets too
*/
<<<<<<< HEAD
func DGALookupOnDNSResponsesFlowFunction(packet gopacket.Packet) {
	// Flow Functions should be organized into the two sections:

	// 1. Packet Checking
	// Attempt to retrieve a copy of the DNS layer in the given packet
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		// no dns layer present, ignore packet
		return
	}

	// 2. Packet Action - do immediately
	// Retrieve the data Packet
	dnsData, _ := dnsLayer.(*layers.DNS)

	// Check for standard DNS query
	if dnsData.OpCode == layers.DNSOpCodeQuery {
		switch dnsData.QR {
		case false: // Query
			//handleStandardQuery(dnsData)
			break
		case true: // Response
			handleStandardResponse(dnsData)
			break
		}
	}
}

func handleStandardResponse(dnsData *layers.DNS) {
	fmt.Println("--> DNS Response found...")
	// Cycle through all the domainNames questioned, checking for DGA domain names using in-mem db
	for _, DNSquestion := range dnsData.Questions {
		domainName := string(DNSquestion.Name)

		// in-mem lookup w/ redis
		returnVal := DGARedisClient.Get(domainName)
		if returnVal.Err() != redis.Nil {
			for _, answer := range dnsData.Answers {
				// Note: These DGA shouldn't have multiple IP address, but unclear
				// Should block
				addIPToTrace(answer.IP.String())
			}
		} else {
			fmt.Println("- Lookup failed, but use anyway for the sake of testing")
			for _, answer := range dnsData.Answers {
				if answer.IP == nil {
					continue
				}

				addIPToTrace(answer.IP.String())
			}
		}
	}
=======
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

>>>>>>> 2f758f6ac37b6ecf3a9ac9647b4cc9910f45c5ad
}
