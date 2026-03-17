package sip

import (
	"strings"
	"testing"
)

const sipOptionsResponse = "SIP/2.0 200 OK\r\n" +
	"Via: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK1234abcd;received=10.0.0.1;rport=5060\r\n" +
	"From: <sip:probe@10.0.0.2>;tag=abc123\r\n" +
	"To: <sip:probe@10.0.0.2>;tag=xyz789\r\n" +
	"Call-ID: deadbeef01234567@10.0.0.2\r\n" +
	"CSeq: 1 OPTIONS\r\n" +
	"Contact: <sip:10.0.0.2:5060>\r\n" +
	"Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE\r\n" +
	"Supported: replaces, timer\r\n" +
	"User-Agent: Asterisk PBX 18.12.0\r\n" +
	"Server: Asterisk PBX 18.12.0\r\n" +
	"Accept: application/sdp, application/dialog-info+xml\r\n" +
	"X-Serialnumber: ABC123456\r\n" +
	"X-Custom-Header: vendor-specific-value\r\n" +
	"Content-Length: 0\r\n" +
	"\r\n"

const sipRegister401Response = "SIP/2.0 401 Unauthorized\r\n" +
	"Via: SIP/2.0/TCP 10.0.0.1;branch=z9hG4bK5678efgh;received=10.0.0.1\r\n" +
	"From: <sip:alice@example.com>;tag=reg001\r\n" +
	"To: <sip:alice@example.com>;tag=srv001\r\n" +
	"Call-ID: register-call-001@example.com\r\n" +
	"CSeq: 1 REGISTER\r\n" +
	"WWW-Authenticate: Digest realm=\"example.com\", nonce=\"abc123nonce\", algorithm=MD5, qop=\"auth\"\r\n" +
	"Server: OpenSIPS 3.2.0\r\n" +
	"Content-Length: 0\r\n" +
	"\r\n"

const sipInviteWithSDP = "SIP/2.0 200 OK\r\n" +
	"Via: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bKinvite01;received=10.0.0.1;rport=5060\r\n" +
	"From: <sip:caller@example.com>;tag=inv001\r\n" +
	"To: <sip:callee@example.com>;tag=inv002\r\n" +
	"Call-ID: invite-call-001@example.com\r\n" +
	"CSeq: 1 INVITE\r\n" +
	"Contact: <sip:callee@192.168.1.100:5060>\r\n" +
	"Content-Type: application/sdp\r\n" +
	"Content-Length: 310\r\n" +
	"\r\n" +
	"v=0\r\n" +
	"o=callee 1234567890 1234567890 IN IP4 192.168.1.100\r\n" +
	"s=Phone Call\r\n" +
	"c=IN IP4 192.168.1.100\r\n" +
	"t=0 0\r\n" +
	"m=audio 10000 RTP/AVP 0 8 101\r\n" +
	"a=rtpmap:0 PCMU/8000\r\n" +
	"a=rtpmap:8 PCMA/8000\r\n" +
	"a=rtpmap:101 telephone-event/8000\r\n" +
	"a=fmtp:101 0-16\r\n" +
	"a=sendrecv\r\n"

const sipInviteWithSRTP = "SIP/2.0 200 OK\r\n" +
	"Via: SIP/2.0/TLS 10.0.0.1;branch=z9hG4bKsrtp01\r\n" +
	"From: <sip:caller@secure.example.com>;tag=sec001\r\n" +
	"To: <sip:callee@secure.example.com>;tag=sec002\r\n" +
	"Call-ID: secure-call-001@secure.example.com\r\n" +
	"CSeq: 1 INVITE\r\n" +
	"Contact: <sips:callee@192.168.1.200:5061>\r\n" +
	"Content-Type: application/sdp\r\n" +
	"Content-Length: 400\r\n" +
	"\r\n" +
	"v=0\r\n" +
	"o=callee 9876543210 9876543210 IN IP4 192.168.1.200\r\n" +
	"s=Secure Call\r\n" +
	"c=IN IP4 192.168.1.200\r\n" +
	"t=0 0\r\n" +
	"m=audio 20000 RTP/SAVP 0 8\r\n" +
	"a=rtpmap:0 PCMU/8000\r\n" +
	"a=rtpmap:8 PCMA/8000\r\n" +
	"a=fingerprint:sha-256 AB:CD:EF:01:23:45:67:89\r\n" +
	"a=setup:actpass\r\n" +
	"a=ice-ufrag:abcd1234\r\n" +
	"a=ice-pwd:efgh5678ijkl9012\r\n" +
	"a=sendrecv\r\n"

const sip500Response = "SIP/2.0 500 Internal Server Error\r\n" +
	"Via: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bKerr01\r\n" +
	"From: <sip:probe@10.0.0.2>;tag=err001\r\n" +
	"To: <sip:probe@10.0.0.2>;tag=err002\r\n" +
	"Call-ID: error-call-001@10.0.0.2\r\n" +
	"CSeq: 1 OPTIONS\r\n" +
	"Server: Kamailio 5.6.0\r\n" +
	"Content-Length: 0\r\n" +
	"\r\n"

const sip404Response = "SIP/2.0 404 Not Found\r\n" +
	"Via: SIP/2.0/TCP 10.0.0.1;branch=z9hG4bKnf01\r\n" +
	"From: <sip:nobody@10.0.0.3>;tag=nf001\r\n" +
	"To: <sip:nobody@10.0.0.3>;tag=nf002\r\n" +
	"Call-ID: notfound-001@10.0.0.3\r\n" +
	"CSeq: 1 REGISTER\r\n" +
	"Server: FreeSWITCH 1.10.9\r\n" +
	"Content-Length: 0\r\n" +
	"\r\n"

func TestParseStatusLine200(t *testing.T) {
	resp, err := ParseSIPResponse([]byte(sipOptionsResponse))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusLine.Version != "SIP/2.0" {
		t.Errorf("expected version SIP/2.0, got %s", resp.StatusLine.Version)
	}
	if resp.StatusLine.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusLine.StatusCode)
	}
	if resp.StatusLine.Reason != "OK" {
		t.Errorf("expected reason OK, got %s", resp.StatusLine.Reason)
	}
}

func TestParseStatusLine401(t *testing.T) {
	resp, err := ParseSIPResponse([]byte(sipRegister401Response))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusLine.StatusCode != 401 {
		t.Errorf("expected status 401, got %d", resp.StatusLine.StatusCode)
	}
	if resp.StatusLine.Reason != "Unauthorized" {
		t.Errorf("expected reason Unauthorized, got %s", resp.StatusLine.Reason)
	}
}

func TestParseStatusLine500(t *testing.T) {
	resp, err := ParseSIPResponse([]byte(sip500Response))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusLine.StatusCode != 500 {
		t.Errorf("expected 500, got %d", resp.StatusLine.StatusCode)
	}
	if resp.Headers.Server != "Kamailio 5.6.0" {
		t.Errorf("expected server Kamailio 5.6.0, got %s", resp.Headers.Server)
	}
}

func TestParseStatusLine404(t *testing.T) {
	resp, err := ParseSIPResponse([]byte(sip404Response))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusLine.StatusCode != 404 {
		t.Errorf("expected 404, got %d", resp.StatusLine.StatusCode)
	}
	if resp.Headers.Server != "FreeSWITCH 1.10.9" {
		t.Errorf("expected server FreeSWITCH 1.10.9, got %s", resp.Headers.Server)
	}
}

func TestParseOptionsHeaders(t *testing.T) {
	resp, err := ParseSIPResponse([]byte(sipOptionsResponse))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	h := resp.Headers
	if h.UserAgent != "Asterisk PBX 18.12.0" {
		t.Errorf("UserAgent: got %q", h.UserAgent)
	}
	if h.Server != "Asterisk PBX 18.12.0" {
		t.Errorf("Server: got %q", h.Server)
	}
	if !strings.Contains(h.Allow, "INVITE") || !strings.Contains(h.Allow, "OPTIONS") {
		t.Errorf("Allow should contain INVITE and OPTIONS, got %q", h.Allow)
	}
	if h.Supported != "replaces, timer" {
		t.Errorf("Supported: got %q", h.Supported)
	}
	if h.CallID != "deadbeef01234567@10.0.0.2" {
		t.Errorf("CallID: got %q", h.CallID)
	}
	if h.CSeq != "1 OPTIONS" {
		t.Errorf("CSeq: got %q", h.CSeq)
	}
	if len(h.Via) != 1 {
		t.Fatalf("expected 1 Via header, got %d", len(h.Via))
	}
	if !strings.Contains(h.Via[0], "branch=z9hG4bK1234abcd") {
		t.Errorf("Via should contain branch, got %q", h.Via[0])
	}
	if h.XSerialNumber != "ABC123456" {
		t.Errorf("X-Serialnumber: got %q", h.XSerialNumber)
	}
	if h.XHeaders == nil || h.XHeaders["x-custom-header"] != "vendor-specific-value" {
		t.Errorf("X-Custom-Header not parsed correctly: %v", h.XHeaders)
	}
	if h.ContentLength != 0 {
		t.Errorf("ContentLength: got %d", h.ContentLength)
	}
}

func TestParseRegister401Headers(t *testing.T) {
	resp, err := ParseSIPResponse([]byte(sipRegister401Response))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Headers.Server != "OpenSIPS 3.2.0" {
		t.Errorf("Server: got %q", resp.Headers.Server)
	}
	if !strings.Contains(resp.Headers.WWWAuthenticate, "Digest") {
		t.Errorf("WWW-Authenticate should contain Digest, got %q", resp.Headers.WWWAuthenticate)
	}
	if !strings.Contains(resp.Headers.WWWAuthenticate, "realm=\"example.com\"") {
		t.Errorf("WWW-Authenticate should contain realm, got %q", resp.Headers.WWWAuthenticate)
	}
}

func TestParseSDPBasic(t *testing.T) {
	resp, err := ParseSIPResponse([]byte(sipInviteWithSDP))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.SDP == nil {
		t.Fatal("SDP should not be nil")
	}

	sdp := resp.SDP
	if sdp.ConnectionIP != "192.168.1.100" {
		t.Errorf("ConnectionIP: got %q", sdp.ConnectionIP)
	}
	if sdp.Version != "0" {
		t.Errorf("Version: got %q", sdp.Version)
	}
	if sdp.SessionName != "Phone Call" {
		t.Errorf("SessionName: got %q", sdp.SessionName)
	}
	if len(sdp.MediaStreams) != 1 {
		t.Fatalf("expected 1 media stream, got %d", len(sdp.MediaStreams))
	}

	stream := sdp.MediaStreams[0]
	if stream.Type != "audio" {
		t.Errorf("stream type: got %q", stream.Type)
	}
	if stream.Port != 10000 {
		t.Errorf("stream port: got %d", stream.Port)
	}
	if stream.Protocol != "RTP/AVP" {
		t.Errorf("stream protocol: got %q", stream.Protocol)
	}
	if stream.Direction != "sendrecv" {
		t.Errorf("stream direction: got %q", stream.Direction)
	}

	// Check codecs
	if len(stream.Codecs) != 3 {
		t.Fatalf("expected 3 codecs, got %d", len(stream.Codecs))
	}
	if stream.Codecs[0].Name != "PCMU" || stream.Codecs[0].ClockRate != 8000 {
		t.Errorf("codec 0: got %+v", stream.Codecs[0])
	}
	if stream.Codecs[1].Name != "PCMA" || stream.Codecs[1].ClockRate != 8000 {
		t.Errorf("codec 1: got %+v", stream.Codecs[1])
	}
	if stream.Codecs[2].Name != "telephone-event" {
		t.Errorf("codec 2: got %+v", stream.Codecs[2])
	}
	if stream.Codecs[2].Fmtp != "0-16" {
		t.Errorf("codec 2 fmtp: got %q", stream.Codecs[2].Fmtp)
	}

	// No SRTP
	if sdp.SupportsSRTP {
		t.Error("should not support SRTP with RTP/AVP")
	}
	if sdp.SupportsDTLSSRTP {
		t.Error("should not support DTLS-SRTP")
	}
	if sdp.SupportsICE {
		t.Error("should not support ICE")
	}
}

func TestParseSDPWithSRTP(t *testing.T) {
	resp, err := ParseSIPResponse([]byte(sipInviteWithSRTP))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.SDP == nil {
		t.Fatal("SDP should not be nil")
	}

	sdp := resp.SDP
	if sdp.ConnectionIP != "192.168.1.200" {
		t.Errorf("ConnectionIP: got %q", sdp.ConnectionIP)
	}
	if !sdp.SupportsSRTP {
		t.Error("expected SupportsSRTP=true for RTP/SAVP")
	}
	if !sdp.SupportsDTLSSRTP {
		t.Error("expected SupportsDTLSSRTP=true for fingerprint attribute")
	}
	if !sdp.SupportsICE {
		t.Error("expected SupportsICE=true for ice-ufrag/ice-pwd")
	}

	if len(sdp.MediaStreams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(sdp.MediaStreams))
	}
	stream := sdp.MediaStreams[0]
	if stream.Port != 20000 {
		t.Errorf("port: got %d", stream.Port)
	}
	if stream.Protocol != "RTP/SAVP" {
		t.Errorf("protocol: got %q", stream.Protocol)
	}
	if stream.Fingerprint != "sha-256 AB:CD:EF:01:23:45:67:89" {
		t.Errorf("fingerprint: got %q", stream.Fingerprint)
	}
	if stream.ICEUfrag != "abcd1234" {
		t.Errorf("ice-ufrag: got %q", stream.ICEUfrag)
	}
	if stream.ICEPwd != "efgh5678ijkl9012" {
		t.Errorf("ice-pwd: got %q", stream.ICEPwd)
	}
	if stream.Setup != "actpass" {
		t.Errorf("setup: got %q", stream.Setup)
	}
}

func TestParseNoSDP(t *testing.T) {
	resp, err := ParseSIPResponse([]byte(sipOptionsResponse))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.SDP != nil {
		t.Error("SDP should be nil when Content-Type is not application/sdp")
	}
}

func TestParseInvalidResponse(t *testing.T) {
	_, err := ParseSIPResponse([]byte(""))
	if err == nil {
		t.Error("expected error for empty response")
	}

	_, err = ParseSIPResponse([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	if err == nil {
		t.Error("expected error for non-SIP response")
	}

	_, err = ParseSIPResponse([]byte("SIP/2.0 notanumber Bad\r\n\r\n"))
	if err == nil {
		t.Error("expected error for invalid status code")
	}
}

func TestBuildSIPRequest(t *testing.T) {
	flags := &Flags{
		Method:    "OPTIONS",
		User:      "probe",
		Domain:    "example.com",
		UserAgent: "zgrab2/sip",
		UseUDP:    true,
	}

	target := zgrab2TestTarget("192.168.1.1")

	data, err := BuildSIPRequest(flags, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := string(data)
	if !strings.HasPrefix(msg, "OPTIONS sip:probe@example.com SIP/2.0\r\n") {
		t.Errorf("bad request line: %q", strings.SplitN(msg, "\r\n", 2)[0])
	}
	if !strings.Contains(msg, "Via: SIP/2.0/UDP") {
		t.Error("missing UDP Via header")
	}
	if !strings.Contains(msg, "Max-Forwards: 70") {
		t.Error("missing Max-Forwards")
	}
	if !strings.Contains(msg, "Call-ID:") {
		t.Error("missing Call-ID")
	}
	if !strings.Contains(msg, "CSeq: 1 OPTIONS") {
		t.Error("missing or wrong CSeq")
	}
	if !strings.Contains(msg, "User-Agent: zgrab2/sip") {
		t.Error("missing User-Agent")
	}
	if !strings.Contains(msg, "Content-Length: 0") {
		t.Error("missing Content-Length")
	}
	if !strings.Contains(msg, ";branch=z9hG4bK") {
		t.Error("Via branch should start with z9hG4bK (RFC 3261)")
	}
}

func TestBuildSIPRequestINVITEWithSDP(t *testing.T) {
	flags := &Flags{
		Method:    "INVITE",
		User:      "alice",
		Domain:    "example.com",
		UserAgent: "zgrab2/sip",
		NoSDP:     false,
	}

	target := zgrab2TestTarget("192.168.1.1")

	data, err := BuildSIPRequest(flags, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := string(data)
	if !strings.HasPrefix(msg, "INVITE sip:alice@example.com SIP/2.0\r\n") {
		t.Errorf("bad request line")
	}
	if !strings.Contains(msg, "Content-Type: application/sdp") {
		t.Error("missing Content-Type for SDP")
	}
	if !strings.Contains(msg, "m=audio") {
		t.Error("missing SDP m= line")
	}
	if !strings.Contains(msg, "a=rtpmap:0 PCMU/8000") {
		t.Error("missing PCMU rtpmap")
	}
	if strings.Contains(msg, "Content-Length: 0") {
		t.Error("Content-Length should not be 0 with SDP body")
	}
}

func TestBuildSIPRequestINVITENoSDP(t *testing.T) {
	flags := &Flags{
		Method:    "INVITE",
		User:      "bob",
		Domain:    "example.com",
		UserAgent: "zgrab2/sip",
		NoSDP:     true,
	}

	target := zgrab2TestTarget("192.168.1.1")

	data, err := BuildSIPRequest(flags, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := string(data)
	if strings.Contains(msg, "Content-Type: application/sdp") {
		t.Error("should not have Content-Type when NoSDP is set")
	}
	if !strings.Contains(msg, "Content-Length: 0") {
		t.Error("Content-Length should be 0 with no SDP")
	}
}
