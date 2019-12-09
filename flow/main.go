package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"
)

// ! Exported variables
// * Program parameters
var pcapFilePath string
var NATSSwitch string
var networkDeviceInterfaceName string

// * Configuration variables
var NATSconfig FlowConfig

// * WaitGroup for the main thread
var mainThreadWaitGroup sync.WaitGroup

// * Temporary variables for recording data in CSV file
// TODO update to live analysis
var domainNameFile *os.File
var domainNameCSVWriter *csv.Writer

func init() {
	// Extracting program parameters passed in from command-line
	flag.StringVar(&pcapFilePath, "f", "no.pcap", "For offline parsing, provide filepath to .pcap file to be parsed")
	flag.StringVar(&networkDeviceInterfaceName, "i", "no.interface", "Declare an network interface for online parsing")
	flag.StringVar(&NATSSwitch, "NATS", "off", "Provide 'on' to indicate that packets are to be received from NATS")
	flag.String("NATSconfig", "NATSconfig.toml", "Configuration file for NATS")
}

func main() {
	fmt.Println("########### INITIATING FLOW ############")
	fmt.Println("## Parsing flags...")
	flag.Parse()

	fmt.Println("## Configuring NATS connection...")
	NATSconfig = GetNATSConfig()

	fmt.Println("## Parsing YAML for API requests to SDN controller...")
	SDNControllerParseYamlConfig("SDNControllerAPIconfig.yaml")

	// Connecting to redis DB
	go initRedisDB()

	// TODO Sets up data to written to csv - to be removed
	setUpCSVOutputFile()

	fmt.Println("## Initialise the Channels with packet flow...")
	// Moved into functions for the sake of simplifying main func's flow
	// * Includes setting up workers
	initialiseChannelsForNATS()
	initialiseChannelsForNetworkInterfaceOrPcap()

	fmt.Println("Main thread waiting...")
	mainThreadWaitGroup.Wait()

	fmt.Println("Flushing writers...")
	flushWriters()

	fmt.Println("***FINISHED***")
}

// TODO to be removed - should be replaced with live analysis
func writeToCSV(domainName string, dstIP string, successful string, ipAddress string, malwareFamily string) {
	// Construct rows
	s := make([]string, 6)
	s[0] = strconv.FormatInt(time.Now().Unix(), 10)
	s[1] = dstIP
	s[2] = domainName
	s[3] = successful
	s[4] = ipAddress
	s[5] = malwareFamily

	// write to file
	domainNameCSVWriter.Write(s)
}

// TODO to be removed - should be replaced with live analysis
func setUpCSVOutputFile() {
	baseFileName := "domainNamesFound"
	i := 0

	for {
		potentialFilePath := baseFileName + "_" + strconv.Itoa(i) + ".csv"
		_, err := os.Stat(potentialFilePath)
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
