// Package sip provides a zgrab2 module for scanning SIP (Session Initiation Protocol) servers.
//
// The module sends SIP requests (OPTIONS, REGISTER, or INVITE) to targets and parses the
// structured response, extracting security-relevant information such as:
//   - Server vendor/version from User-Agent and Server headers
//   - Supported SIP methods from the Allow header
//   - SDP media details including codec information
//   - Security features: SRTP, DTLS-SRTP, ICE support
//   - Vendor-specific headers (X-Serialnumber, etc.)
//
// Usage examples:
//
//	echo "192.168.1.1" | zgrab2 sip --port 5060 --method OPTIONS
//	echo "192.168.1.1" | zgrab2 sip --port 5060 --method OPTIONS --udp
//	echo "192.168.1.1" | zgrab2 sip --port 5061 --method REGISTER --tls --from "sip:scanner@example.com"
//	echo "192.168.1.1" | zgrab2 sip --port 5060 --method INVITE --domain example.com --user alice
//
// Example JSON output (abbreviated):
//
//	{
//	  "ip": "192.168.1.1",
//	  "data": {
//	    "sip": {
//	      "status": "success",
//	      "protocol": "sip",
//	      "result": {
//	        "response": {
//	          "status_line": { "version": "SIP/2.0", "status_code": 200, "reason": "OK" },
//	          "headers": {
//	            "user_agent": "Asterisk PBX 18.0.0",
//	            "server": "Asterisk PBX 18.0.0",
//	            "allow": "INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO",
//	            "supported": "replaces, timer"
//	          },
//	          "sdp": {
//	            "connection_ip": "192.168.1.1",
//	            "media_streams": [{ "type": "audio", "port": 10000, "protocol": "RTP/AVP", ... }],
//	            "supports_srtp": false
//	          }
//	        },
//	        "transport": "udp"
//	      }
//	    }
//	  }
//	}
//
// Security analysis notes:
//   - User-Agent/Server headers reveal vendor and firmware version for CVE matching
//   - Allow header shows which methods are enabled (INVITE, REGISTER, etc.)
//   - SDP analysis reveals media encryption support (SRTP, DTLS-SRTP, ICE)
//   - X-Serialnumber and other vendor headers can fingerprint device models
//   - Responses to REGISTER may reveal authentication requirements
package sip

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/zmap/zgrab2"
)

// Flags contains the command-line flags for the SIP module.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.UDPFlags  `group:"UDP Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`

	// Transport selection
	UseUDP bool `long:"udp" description:"Use UDP transport (default is TCP)"`
	UseTLS bool `long:"tls" description:"Use TLS transport (SIPS). Implies TCP."`

	// SIP method
	Method string `long:"method" default:"OPTIONS" description:"SIP method to use: OPTIONS, REGISTER, or INVITE"`

	// SIP URI/header fields
	From    string `long:"from" description:"SIP From URI (e.g. sip:scanner@example.com). Auto-generated if empty."`
	To      string `long:"to" description:"SIP To URI. Auto-generated from target if empty."`
	Contact string `long:"contact" description:"SIP Contact URI. Auto-generated if empty."`
	User    string `long:"user" default:"probe" description:"Username part for SIP URIs"`
	Domain  string `long:"domain" description:"Domain part for SIP URIs. Uses target host if empty."`

	// SDP
	NoSDP bool `long:"no-sdp" description:"Do not include SDP body in INVITE requests"`

	// Timeouts and retries for UDP
	ReadTimeout int `long:"read-timeout" default:"5000" description:"Read timeout in milliseconds"`
	MaxTries    int `long:"max-tries" default:"3" description:"Number of retries for UDP transport"`

	// Custom User-Agent
	UserAgent string `long:"user-agent" default:"zgrab2/sip" description:"User-Agent header value"`
}

// Module implements the zgrab2.ScanModule interface.
type Module struct{}

// Scanner implements the zgrab2.Scanner interface for SIP.
type Scanner struct {
	config *Flags
}

// Results is the top-level result returned by the SIP scan.
type Results struct {
	Response  *SIPResponse `json:"response,omitempty"`
	Transport string       `json:"transport,omitempty"`
	TLSLog    *zgrab2.TLSLog `json:"tls,omitempty"`
	RawRequest  string `json:"raw_request,omitempty" zgrab:"debug"`
	RawResponse string `json:"raw_response,omitempty" zgrab:"debug"`
}

// RegisterModule is called by modules/sip.go to register the SIP scanner.
func RegisterModule() {
	var m Module
	_, err := zgrab2.AddCommand("sip", "SIP", m.Description(), 5060, &m)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a new default flags object.
func (m *Module) NewFlags() any {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (m *Module) Description() string {
	return "Send SIP requests (OPTIONS/REGISTER/INVITE) and parse structured responses for security analysis"
}

// Validate checks that the flags are consistent.
func (f *Flags) Validate(args []string) error {
	switch f.Method {
	case "OPTIONS", "REGISTER", "INVITE":
		// valid
	default:
		return fmt.Errorf("unsupported SIP method %q: must be OPTIONS, REGISTER, or INVITE", f.Method)
	}
	if f.UseTLS && f.UseUDP {
		return fmt.Errorf("--tls and --udp are mutually exclusive")
	}
	return nil
}

// Help returns module help text.
func (f *Flags) Help() string {
	return ""
}

// Init initializes the Scanner with the parsed flags.
func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	s.config = f
	return nil
}

// InitPerSender is called once per worker goroutine.
func (s *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the scanner name.
func (s *Scanner) GetName() string {
	return s.config.Name
}

// GetTrigger returns the trigger tag.
func (s *Scanner) GetTrigger() string {
	return s.config.Trigger
}

// Protocol returns the protocol identifier.
func (s *Scanner) Protocol() string {
	return "sip"
}

// Scan performs the SIP scan against the target.
func (s *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	// Build the SIP request
	reqBytes, err := BuildSIPRequest(s.config, target)
	if err != nil {
		return zgrab2.SCAN_UNKNOWN_ERROR, nil, fmt.Errorf("building SIP request: %w", err)
	}

	results := &Results{
		RawRequest: string(reqBytes),
	}

	// Determine transport
	if s.config.UseTLS {
		results.Transport = "tls"
		return s.scanTLS(target, reqBytes, results)
	} else if s.config.UseUDP {
		results.Transport = "udp"
		return s.scanUDP(target, reqBytes, results)
	}
	results.Transport = "tcp"
	return s.scanTCP(target, reqBytes, results)
}

func (s *Scanner) scanUDP(target zgrab2.ScanTarget, req []byte, results *Results) (zgrab2.ScanStatus, any, error) {
	readTimeout := time.Duration(s.config.ReadTimeout) * time.Millisecond

	var lastErr error
	for try := 0; try < s.config.MaxTries; try++ {
		conn, err := target.OpenUDP(&s.config.BaseFlags, &s.config.UDPFlags)
		if err != nil {
			lastErr = err
			continue
		}

		// Set deadline for write+read
		conn.SetDeadline(time.Now().Add(readTimeout))

		_, err = conn.Write(req)
		if err != nil {
			conn.Close()
			lastErr = err
			continue
		}

		buf := make([]byte, 65535)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			lastErr = err
			continue
		}

		raw := buf[:n]
		results.RawResponse = string(raw)
		resp, parseErr := ParseSIPResponse(raw)
		if parseErr != nil {
			return zgrab2.SCAN_PROTOCOL_ERROR, results, parseErr
		}
		results.Response = resp
		return zgrab2.SCAN_SUCCESS, results, nil
	}
	return zgrab2.TryGetScanStatus(lastErr), results, lastErr
}

func (s *Scanner) scanTCP(target zgrab2.ScanTarget, req []byte, results *Results) (zgrab2.ScanStatus, any, error) {
	conn, err := target.Open(&s.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()

	return s.scanStream(conn, req, results)
}

func (s *Scanner) scanTLS(target zgrab2.ScanTarget, req []byte, results *Results) (zgrab2.ScanStatus, any, error) {
	conn, err := target.Open(&s.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	tlsConn, err := s.config.TLSFlags.GetTLSConnectionForTarget(conn, &target)
	if err != nil {
		conn.Close()
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	if err = tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return zgrab2.TryGetScanStatus(err), results, err
	}
	results.TLSLog = tlsConn.GetLog()

	status, r, scanErr := s.scanStream(tlsConn, req, results)
	tlsConn.Close()
	return status, r, scanErr
}

func (s *Scanner) scanStream(conn net.Conn, req []byte, results *Results) (zgrab2.ScanStatus, any, error) {
	readTimeout := time.Duration(s.config.ReadTimeout) * time.Millisecond

	_, err := conn.Write(req)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), results, err
	}

	// Read response: use ReadAvailableWithOptions for stream-based reading
	data, err := zgrab2.ReadAvailableWithOptions(conn, 8209, readTimeout, 0, 65535)
	if err != nil && err != io.EOF {
		if len(data) == 0 {
			return zgrab2.TryGetScanStatus(err), results, err
		}
		// We have some data despite the error; try to parse it
	}

	if len(data) == 0 {
		return zgrab2.SCAN_IO_TIMEOUT, results, fmt.Errorf("no response received")
	}

	results.RawResponse = string(data)
	resp, parseErr := ParseSIPResponse(data)
	if parseErr != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, results, parseErr
	}
	results.Response = resp
	return zgrab2.SCAN_SUCCESS, results, nil
}
