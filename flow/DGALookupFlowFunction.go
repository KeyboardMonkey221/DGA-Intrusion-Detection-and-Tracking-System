package main

import (
	"fmt"

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
	fmt.Println("## Initialising flow function DGALookup")
	return packetFlowFunction(DGALookupOnDNSResponsesFlowFunction)
}

/* DGALookupOnDNSQueriesFlowFunction
Designed to look for DNS layers and check whether the domain
name is present in the in-memory database

If found, then the function will create add a new flow function to trace the ip conversation
and create a new channel as well for the new flow function to direct packets too
*/
func DGALookupOnDNSResponsesFlowFunction(packet gopacket.Packet) {
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
	// Cycle through all the domainNames questioned, checking for DGA domain names using in-mem db
	for _, DNSquestion := range dnsData.Questions {
		domainName := string(DNSquestion.Name)

		// in-mem lookup w/ redis
		returnVal := DGARedisClient.Get(domainName)
		if returnVal.Err() != redis.Nil {
			fmt.Println("Malware Found: ", domainName)
			for _, answer := range dnsData.Answers {
				// Note: These DGA shouldn't have multiple IP address, but unclear
				// Should block
				addIPToTrace(answer.IP.String())
			}
		} else {
			/*
				fmt.Println("- Lookup failed, but use anyway for the sake of testing")
				for _, answer := range dnsData.Answers {
					if answer.IP == nil {
						continue
					}

					addIPToTrace(answer.IP.String())
				}
			*/
		}
	}
}
