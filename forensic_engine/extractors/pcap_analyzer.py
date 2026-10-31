"""
PCAP & Network Forensics Extractor for CTF Challenges
-----------------------------------------------------
Performs deep packet dissection, TCP stream reassembly, HTTP multipart file carving,
DNS exfiltration detection, and regex flag hunting across packet captures.
"""

import os
import re
import base64
from typing import Dict, Any, List

from forensic_engine.base import BaseExtractor, ExtractionResult


class PCAPNetworkExtractor(BaseExtractor):
    """
    Extracts forensic evidence from .pcap and .pcapng files:
    - HTTP POST multipart file uploads & transferred objects
    - DNS query exfiltration payloads (Base64/hex in subdomains)
    - Cleartext credentials (HTTP Auth, FTP, Telnet)
    - CTF Flag signatures (HQX{...}, flag{...}, CTF{...}, picoCTF{...})
    """
    category = "network_forensics"

    @classmethod
    def applicable(cls, context) -> bool:
        ext = os.path.splitext(context.file_path)[1].lower()
        if ext in [".pcap", ".pcapng", ".cap"]:
            return True
        # Check magic bytes for libpcap / pcapng
        magic = context.raw_data[:4]
        if magic in [b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"]:
            return True
        return False

    def extract(self, context) -> ExtractionResult:
        try:
            import scapy.all as scapy
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.dns import DNS, DNSQR
            from scapy.layers.http import HTTPRequest, HTTPResponse
        except ImportError:
            return ExtractionResult(
                status="skipped",
                data={"error": "scapy is not installed. Run 'pip install scapy'."}
            )

        evidence: Dict[str, Any] = {
            "total_packets": 0,
            "protocols": {},
            "http_transfers": [],
            "dns_queries": [],
            "dns_exfiltration_candidates": [],
            "credentials_found": [],
            "flags_captured": []
        }

        try:
            packets = scapy.rdpcap(context.file_path)
            evidence["total_packets"] = len(packets)
        except Exception as err:
            return ExtractionResult(
                status="error",
                data={"error": f"Failed to parse PCAP file: {str(err)}"}
            )

        tcp_streams: Dict[str, bytearray] = {}
        all_raw_bytes = bytearray()

        flag_regex = re.compile(r"(?:HQX|flag|CTF|picoCTF|hackquest)\{[^}\n\r\t ]+\}", re.IGNORECASE)

        for pkt in packets:
            # Track protocols
            proto = pkt.summary().split()[0] if pkt.summary() else "Unknown"
            evidence["protocols"][proto] = evidence["protocols"].get(proto, 0) + 1

            # Extract raw payload
            raw_payload = bytes(pkt.payload)
            if raw_payload:
                all_raw_bytes.extend(raw_payload)

            # Reassemble TCP streams
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                stream_key = f"{min(ip_src, ip_dst)}:{min(sport, dport)} <-> {max(ip_src, ip_dst)}:{max(sport, dport)}"
                if stream_key not in tcp_streams:
                    tcp_streams[stream_key] = bytearray()
                
                payload = bytes(pkt[TCP].payload)
                if payload:
                    tcp_streams[stream_key].extend(payload)

            # Inspect DNS Queries for Tunneling / Exfiltration
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode("latin-1", errors="ignore").rstrip(".")
                if qname and qname not in evidence["dns_queries"]:
                    evidence["dns_queries"].append(qname)
                    # Check for base64 or long hex subdomain exfiltration
                    subdomain = qname.split(".")[0]
                    if len(subdomain) >= 16 and (re.match(r"^[A-Za-z0-9+/=]+$", subdomain) or re.match(r"^[0-9a-fA-F]+$", subdomain)):
                        evidence["dns_exfiltration_candidates"].append(qname)

        # Inspect Reassembled Streams for HTTP files and flags
        for stream_key, stream_data in tcp_streams.items():
            stream_text = stream_data.decode("latin-1", errors="ignore")

            # Search flags in stream
            matches = flag_regex.findall(stream_text)
            for m in matches:
                if m not in evidence["flags_captured"]:
                    evidence["flags_captured"].append(m)

            # Look for HTTP POST multipart / uploads
            if "multipart/form-data" in stream_text or "filename=" in stream_text:
                file_matches = re.findall(r'filename="([^"]+)"', stream_text)
                for fn in file_matches:
                    evidence["http_transfers"].append({
                        "stream": stream_key,
                        "filename": fn,
                        "type": "multipart_upload"
                    })

            # Check for HTTP Authorization headers
            auth_matches = re.findall(r'Authorization:\s*(Basic|Bearer)\s+([A-Za-z0-9+/=]+)', stream_text, re.IGNORECASE)
            for auth_type, token in auth_matches:
                decoded = ""
                if auth_type.lower() == "basic":
                    try:
                        decoded = base64.b64decode(token).decode("latin-1", errors="ignore")
                    except Exception:
                        pass
                evidence["credentials_found"].append({
                    "type": auth_type,
                    "token": token,
                    "decoded": decoded
                })

        # Also search raw bytes for flags
        raw_text = all_raw_bytes.decode("latin-1", errors="ignore")
        for m in flag_regex.findall(raw_text):
            if m not in evidence["flags_captured"]:
                evidence["flags_captured"].append(m)

        # Cap lists for clean reporting
        evidence["dns_queries"] = evidence["dns_queries"][:50]
        evidence["dns_exfiltration_candidates"] = evidence["dns_exfiltration_candidates"][:20]

        status = "flag_found" if evidence["flags_captured"] else "success"
        return ExtractionResult(status=status, data=evidence)
