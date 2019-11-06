package main

<<<<<<< HEAD
import (
	"fmt"

	"github.com/google/gopacket"
)
=======
import "github.com/google/gopacket"
>>>>>>> 2f758f6ac37b6ecf3a9ac9647b4cc9910f45c5ad

// Could implement a tree like structure later on for speed
// A packet being parsed successfully by one function probably mean
// there's no point checking another
type packetFlowFunction func(gopacket.Packet)

// This global slice stores all of the functions (* func) that will be called
// on incoming packets and direct flow to their respective channels
<<<<<<< HEAD
// Future development: should implement a tree - if one check passes, then maybe you don't need check something else further down the stage
=======
>>>>>>> 2f758f6ac37b6ecf3a9ac9647b4cc9910f45c5ad
var packetFlowFunctions [](packetFlowFunction)

// Given a channel of gopacket.Packet, apply various functions that will parse packets
// into channels (up to them where and in what form)
// All functions should take COPIES of the packet, never the source (other functions may need it)
// Intended to be used in multiple goroutines (as a worker)
func parsePacketsWorker(incomingPackets <-chan gopacket.Packet) {
<<<<<<< HEAD
	fmt.Println("Parse a packet")
=======
>>>>>>> 2f758f6ac37b6ecf3a9ac9647b4cc9910f45c5ad
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

// **
/*
func filterPacketThroughFlowFunctions(packet gopacket.Packet) {
	for _, flowFunction := range packetFlowFunctions {
		// Note: the responsiblity of decoding the packet lies with the flowFunction
		// In the future, we could have a decoding layer that pushes it into channels that expect a particular
		// format. then flow functions that want a particular decoding structure can attach themselves
		// to the appropriate channel

		// Also it is the responsibility of the flow function to place it into their channel
		flowFunction(packet)
	}
}
*/
