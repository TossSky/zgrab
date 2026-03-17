package sip

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/zmap/zgrab2"
)

// BuildSIPRequest constructs a raw SIP request message based on the given flags and target.
func BuildSIPRequest(flags *Flags, target zgrab2.ScanTarget) ([]byte, error) {
	host := target.Host()
	domain := flags.Domain
	if domain == "" {
		domain = host
	}
	user := flags.User

	// Build Request-URI
	requestURI := fmt.Sprintf("sip:%s@%s", user, domain)

	// Generate unique identifiers
	callID := generateCallID(domain)
	fromTag := generateTag()
	branch := generateBranch()

	// Resolve From URI
	fromURI := flags.From
	if fromURI == "" {
		fromURI = fmt.Sprintf("sip:%s@%s", user, domain)
	}

	// Resolve To URI
	toURI := flags.To
	if toURI == "" {
		toURI = requestURI
	}

	// Resolve Contact URI
	contactURI := flags.Contact
	if contactURI == "" {
		contactURI = fmt.Sprintf("sip:%s@%s", user, domain)
	}

	// Determine the Via transport tag
	transport := "TCP"
	if flags.UseUDP {
		transport = "UDP"
	}
	if flags.UseTLS {
		transport = "TLS"
	}

	// Build headers
	var b strings.Builder

	// Request line
	fmt.Fprintf(&b, "%s %s SIP/2.0\r\n", flags.Method, requestURI)

	// Via
	fmt.Fprintf(&b, "Via: SIP/2.0/%s %s;branch=%s;rport\r\n", transport, host, branch)

	// Max-Forwards
	b.WriteString("Max-Forwards: 70\r\n")

	// To
	fmt.Fprintf(&b, "To: <%s>\r\n", toURI)

	// From (with tag)
	fmt.Fprintf(&b, "From: <%s>;tag=%s\r\n", fromURI, fromTag)

	// Call-ID
	fmt.Fprintf(&b, "Call-ID: %s\r\n", callID)

	// CSeq
	fmt.Fprintf(&b, "CSeq: 1 %s\r\n", flags.Method)

	// Contact
	fmt.Fprintf(&b, "Contact: <%s>\r\n", contactURI)

	// User-Agent
	fmt.Fprintf(&b, "User-Agent: %s\r\n", flags.UserAgent)

	// Build SDP body for INVITE if requested
	var sdpBody string
	if flags.Method == "INVITE" && !flags.NoSDP {
		sdpBody = buildSDP(host, user)
	}

	if sdpBody != "" {
		fmt.Fprintf(&b, "Content-Type: application/sdp\r\n")
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(sdpBody))
	} else {
		b.WriteString("Content-Length: 0\r\n")
	}

	// End of headers
	b.WriteString("\r\n")

	// Body
	if sdpBody != "" {
		b.WriteString(sdpBody)
	}

	return []byte(b.String()), nil
}

// buildSDP generates a minimal SDP body for an INVITE request with one audio stream
// using G.711 u-law (PCMU) codec.
func buildSDP(host, user string) string {
	sessionID := randomNumString(10)
	var b strings.Builder
	fmt.Fprintf(&b, "v=0\r\n")
	fmt.Fprintf(&b, "o=%s %s %s IN IP4 %s\r\n", user, sessionID, sessionID, host)
	fmt.Fprintf(&b, "s=zgrab2 SIP Scan\r\n")
	fmt.Fprintf(&b, "c=IN IP4 %s\r\n", host)
	fmt.Fprintf(&b, "t=0 0\r\n")
	fmt.Fprintf(&b, "m=audio 49170 RTP/AVP 0 8 101\r\n")
	fmt.Fprintf(&b, "a=rtpmap:0 PCMU/8000\r\n")
	fmt.Fprintf(&b, "a=rtpmap:8 PCMA/8000\r\n")
	fmt.Fprintf(&b, "a=rtpmap:101 telephone-event/8000\r\n")
	fmt.Fprintf(&b, "a=fmtp:101 0-16\r\n")
	fmt.Fprintf(&b, "a=sendrecv\r\n")
	return b.String()
}

func generateCallID(domain string) string {
	return fmt.Sprintf("%s@%s", randomHex(16), domain)
}

func generateTag() string {
	return randomHex(8)
}

func generateBranch() string {
	// RFC 3261 requires branch to start with "z9hG4bK"
	return "z9hG4bK" + randomHex(12)
}

func randomHex(length int) string {
	const hex = "0123456789abcdef"
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(16))
		if err != nil {
			b[i] = '0'
		} else {
			b[i] = hex[n.Int64()]
		}
	}
	return string(b)
}

func randomNumString(length int) string {
	const digits = "0123456789"
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			b[i] = '0'
		} else {
			b[i] = digits[n.Int64()]
		}
	}
	return string(b)
}
