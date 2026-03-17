# zschema sub-schema for zgrab2's SIP module
# Registers zgrab2-sip globally, and sip with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

from . import zgrab2

sip_codec = SubRecord(
    {
        "payload_type": Signed32BitInteger(),
        "name": String(),
        "clock_rate": Signed32BitInteger(),
        "params": String(),
        "fmtp": String(),
    }
)

sip_media_stream = SubRecord(
    {
        "type": String(),
        "port": Signed32BitInteger(),
        "protocol": String(),
        "formats": ListOf(String()),
        "codecs": ListOf(sip_codec),
        "direction": String(),
        "ice_ufrag": String(),
        "ice_pwd": String(),
        "fingerprint": String(),
        "setup": String(),
    }
)

sip_sdp_info = SubRecord(
    {
        "version": String(),
        "origin": String(),
        "session_name": String(),
        "connection_ip": String(),
        "media_streams": ListOf(sip_media_stream),
        "supports_srtp": Boolean(),
        "supports_dtls_srtp": Boolean(),
        "supports_ice": Boolean(),
    }
)

sip_status_line = SubRecord(
    {
        "version": String(),
        "status_code": Signed32BitInteger(),
        "reason": String(),
    }
)

sip_headers = SubRecord(
    {
        "from": String(),
        "to": String(),
        "call_id": String(),
        "cseq": String(),
        "via": ListOf(String()),
        "allow": String(),
        "supported": String(),
        "user_agent": String(),
        "server": String(),
        "x_serialnumber": String(),
        "accept": String(),
        "accept_contact": String(),
        "content_type": String(),
        "content_length": Signed32BitInteger(),
        "contact": String(),
        "www_authenticate": String(),
    }
)

sip_response = SubRecord(
    {
        "status_line": sip_status_line,
        "headers": sip_headers,
        "sdp": sip_sdp_info,
    }
)

sip_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "response": sip_response,
                "transport": String(),
                "tls": zgrab2.tls_log,
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-sip", sip_scan_response)

zgrab2.register_scan_response_type("sip", sip_scan_response)
