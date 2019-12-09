package main

import (
	"fmt"

	"github.com/go-redis/redis"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/*
var domainNameFile *os.File
var domainNameCSVWriter *csv.Writer
*/
// Sets up the context before a flowFunction
// Must return a flow function that will perform the checks required on incoming packets
// and look to delegate work accordingly
func initDGALookupOnDNSResponsesFlowFunction() packetFlowFunction {
	fmt.Println("## Initialising flow function DGALookup")

	/*
		var err error
		domainNameFile, err = os.Create("domainNamesFound.csv")
		if err != nil {
			log.Fatal("failed to create file")
		}

		domainNameCSVWriter = csv.NewWriter(domainNameFile)
		defer domainNameCSVWriter.Flush()
	*/
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
	for _, DNSanswer := range dnsData.Answers {
		domainName := string(DNSanswer.Name)

		/*
			max 3 labels
		*/

		// in-mem lookup w/ redis
		returnVal := DGARedisClient.Get(domainName)
		if returnVal.Err() != redis.Nil {
			fmt.Println("Malware Found: ", domainName)

			for _, answer := range dnsData.Answers {
				writeToCSV(domainName, "dst - tbd", "Yes", answer.IP.String(), "")
			}

		} else {
			writeToCSV(domainName, "dst - tbd", "No", "", "")
		}
	}
}

/*
func writeToCSV(domainName string, successful string, ipAddress string) {
	// Construct rows
	s := make([]string, 4)
	s[0] = time.Now().String()
	s[1] = domainName
	s[2] = successful
	s[3] = ipAddress

	// write to file
	domainNameCSVWriter.Write(s)
}
*/
