package main

import (
	"flag"
	"fmt"
	"log"
	"sync"
	"time"
	"os"
	"encoding/csv"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/go-redis/redis"
)

var pcapFilePath string
var NATSSwitch string
var networkDeviceInterfaceName string
var incomingPacketChannelSize int
var mainThreadWaitGroup sync.WaitGroup
var conf FlowConfig
var DNSPacketChannelFromNATS chan DnsPacket
var packetChannelFromPcapHandle chan gopacket.Packet

var domainNameFile *os.File
var domainNameCSVWriter *csv.Writer


func init() {
	flag.StringVar(&pcapFilePath, "f", "no.pcap", "For offline parsing, provide filepath to .pcap file to be parsed")
	flag.StringVar(&networkDeviceInterfaceName, "i", "no.interface", "Declare an network interface for online parsing")
	flag.StringVar(&NATSSwitch, "NATS", "off", "Provide 'on' to indicate that packets are to be received from NATS")
	flag.String("config", "flow.toml", "Configuration file")
}

func main() {
	flag.Parse()
	conf = GetConfig()
	fmt.Println("########### INITIATING FLOW ############")
	go initRedisDB()
	setUpCSVOutputFile()



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
		fmt.Println("* Created worker for NATS...")
		go func() {
			mainThreadWaitGroup.Add(1)
			for DNSPacket := range DNSPacketChannelFromNATS {
				DNSPacketInfo := DNSPacket.GetDnsInfo()

				// Only focus on DNS packets with answers (responses)
				answersRecords := DNSPacketInfo.Answers
				if len(answersRecords) != 0 {
					// iterating with range didn't work
					for i := 0; i < len(answersRecords); i++ {
						domainName := string(answersRecords[i].GetName())
						/*
						Should be swtiched to NATS - better performance (later)
						*/
						returnVal := DGARedisClient.Get(domainName)
						if returnVal.Err() != redis.Nil {
							fmt.Println("Malware Found: ", domainName)
							fmt.Println("-> ", string(answersRecords[i].GetByteData()))
							// Goal is nats will be the messaging service
							// For the moment, can just use restful directly to SDN controller, though the goal will be to use NATS to
							// msg the SDN controller

							// therefore, create a restful server, make sure that the restful requests are correct
							writeToCSV(domainName, "Yes", string(answersRecords[i].GetByteData()))
							
						} else {
							writeToCSV(domainName, "No", "")
						}
					}
				}
			}
		}()
	} else {
		fmt.Println("!! DNS PacketSource offline ")

		// Add the flowFunction to parse for DNS Responses and perform DGA lookups
		addFlowFunction(initDGALookupOnDNSResponsesFlowFunction())
	}

	fmt.Print("!! Opening the pcap handle...")
	//var pcapHandle *pcap.Handle = getpcapHandle()
	//defer pcapHandle.Close()
	fmt.Println("Success")

	fmt.Print("** Initialising packet flow from pcap handle...")
	//packetChannelFromPcapHandle = getPacketsChannelFromHandle(pcapHandle)
	fmt.Println("Success")

	fmt.Println("!! Adding flow functions to parse packets from pcapHandle...")
	addFlowFunction(initIPTraceFlowFunction())
	fmt.Println("@@ Finished")

	fmt.Println("* Create worker Flow Functions...")
	/*
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
			*//*
			for _, flowFunction := range packetFlowFunctions {
				flowFunction(packet)
			}

			packetCounter++
		}
	}()
		*/
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

func writeToCSV(domainName string, successful string, ipAddress string) {
// Construct rows
s := make([]string, 4)
s[0] = strconv.FormatInt(time.Now().Unix(), 10)
s[1] = domainName
s[2] = successful
s[3] = ipAddress

// write to file
domainNameCSVWriter.Write(s)
}

func setUpCSVOutputFile() {
	baseFileName := "domainNamesFound"
	i := 0

	for {
		potentialFilePath := baseFileName + "_" + strconv.Itoa(i) + ".csv"
		_, err := os.Stat(potentialFilePath); 
		if err == nil {
			// File name already exists, don't overwrite
			i++
			continue
		} else {
			// Create file - it doesn't exist
			domainNameFile, err = os.Create(potentialFilePath)
			if err != nil {
				log.Fatal("failed to create file: ", potentialFilePath)
			}
		  
			domainNameCSVWriter = csv.NewWriter(domainNameFile)
			defer domainNameCSVWriter.Flush()

			// end loop 
			break
		}
	}
}