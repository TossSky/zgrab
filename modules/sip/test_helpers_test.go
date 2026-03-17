package sip

import (
	"net"

	"github.com/zmap/zgrab2"
)

// zgrab2TestTarget creates a minimal ScanTarget for testing.
func zgrab2TestTarget(ip string) zgrab2.ScanTarget {
	return zgrab2.ScanTarget{
		IP: net.ParseIP(ip),
	}
}
