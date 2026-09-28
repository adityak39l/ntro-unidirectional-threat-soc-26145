import hashlib
import struct
from typing import Dict, Any, List, Optional

TLS_VERSION_NAMES = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_EC_POINT_FORMATS = 11


def is_grease(value: int) -> bool:
    # RFC 8701 GREASE values (0x0a0a, 0x1a1a, ... 0xfafa) are ignored by JA3
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def _u16_list(data: bytes) -> List[int]:
    return [struct.unpack("!H", data[i:i + 2])[0] for i in range(0, len(data) - 1, 2)]


def build_client_hello(
    ciphers: List[int],
    extensions: Optional[Dict[int, bytes]] = None,
    client_version: int = 0x0303,
    record_version: int = 0x0301,
    sni: str = "",
    groups: Optional[List[int]] = None,
    point_formats: Optional[List[int]] = None,
) -> bytes:
    """Serialise a TLS ClientHello record (used by the traffic simulator and tests)."""
    ext_list = []
    if sni:
        name = sni.encode("ascii")
        entry = struct.pack("!BH", 0, len(name)) + name
        ext_list.append((EXT_SERVER_NAME, struct.pack("!H", len(entry)) + entry))
    if groups is not None:
        body = b"".join(struct.pack("!H", g) for g in groups)
        ext_list.append((EXT_SUPPORTED_GROUPS, struct.pack("!H", len(body)) + body))
    if point_formats is not None:
        ext_list.append((EXT_EC_POINT_FORMATS, struct.pack("!B", len(point_formats)) + bytes(point_formats)))
    for ext_type, ext_data in (extensions or {}).items():
        ext_list.append((ext_type, ext_data))

    ext_bytes = b"".join(struct.pack("!HH", t, len(d)) + d for t, d in ext_list)
    cipher_bytes = b"".join(struct.pack("!H", c) for c in ciphers)

    body = struct.pack("!H", client_version) + bytes(32)          # version + random
    body += b"\x00"                                                 # empty session id
    body += struct.pack("!H", len(cipher_bytes)) + cipher_bytes
    body += b"\x01\x00"                                             # null compression
    if ext_list:
        body += struct.pack("!H", len(ext_bytes)) + ext_bytes

    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16" + struct.pack("!HH", record_version, len(handshake)) + handshake


class TLSFingerprinter:
    @staticmethod
    def extract_ja3(payload: bytes) -> Dict[str, Any]:
        """Parse a plaintext ClientHello and compute its JA3 fingerprint (no decryption)."""
        result = {
            "is_tls": False,
            "ja3_str": "",
            "ja3_hash": "",
            "sni": "",
            "cipher_count": 0,
            "extension_count": 0,
            "tls_version": 0,
            "tls_version_name": "",
            "complete": False,
        }

        if not payload or len(payload) < 9:
            return result
        if payload[0] != 0x16 or payload[1] != 0x03 or payload[5] != 0x01:
            return result

        result["is_tls"] = True
        try:
            pos = 9  # record header (5) + handshake type (1) + handshake length (3)
            client_version = struct.unpack("!H", payload[pos:pos + 2])[0]
            result["tls_version"] = client_version
            result["tls_version_name"] = TLS_VERSION_NAMES.get(client_version, hex(client_version))
            pos += 2 + 32

            sid_len = payload[pos]
            pos += 1 + sid_len

            cs_len = struct.unpack("!H", payload[pos:pos + 2])[0]
            pos += 2
            cipher_bytes = payload[pos:pos + cs_len]
            if len(cipher_bytes) < cs_len:
                return result
            ciphers = [c for c in _u16_list(cipher_bytes) if not is_grease(c)]
            result["cipher_count"] = len(ciphers)
            pos += cs_len

            comp_len = payload[pos]
            pos += 1 + comp_len

            ext_types: List[int] = []
            groups: List[int] = []
            point_formats: List[int] = []
            sni = ""
            if pos + 2 <= len(payload):
                ext_total = struct.unpack("!H", payload[pos:pos + 2])[0]
                pos += 2
                end = pos + ext_total
                if end > len(payload):
                    return result  # truncated capture: cannot produce a faithful JA3
                while pos + 4 <= end:
                    ext_type, ext_len = struct.unpack("!HH", payload[pos:pos + 4])
                    data = payload[pos + 4:pos + 4 + ext_len]
                    pos += 4 + ext_len
                    if is_grease(ext_type):
                        continue
                    ext_types.append(ext_type)
                    if ext_type == EXT_SERVER_NAME and len(data) >= 5:
                        name_len = struct.unpack("!H", data[3:5])[0]
                        sni = data[5:5 + name_len].decode("ascii", errors="replace")
                    elif ext_type == EXT_SUPPORTED_GROUPS and len(data) >= 2:
                        groups = [g for g in _u16_list(data[2:]) if not is_grease(g)]
                    elif ext_type == EXT_EC_POINT_FORMATS and len(data) >= 1:
                        point_formats = list(data[1:1 + data[0]])

            ja3_str = ",".join([
                str(client_version),
                "-".join(str(c) for c in ciphers),
                "-".join(str(e) for e in ext_types),
                "-".join(str(g) for g in groups),
                "-".join(str(p) for p in point_formats),
            ])
            result.update({
                "ja3_str": ja3_str,
                "ja3_hash": hashlib.md5(ja3_str.encode("ascii")).hexdigest(),
                "sni": sni,
                "extension_count": len(ext_types),
                "complete": True,
            })
        except (IndexError, struct.error):
            pass

        return result

    @staticmethod
    def extract_splt(packet_lengths: List[int], max_packets: int = 30) -> List[int]:
        splt = list(packet_lengths[:max_packets])
        if len(splt) < max_packets:
            splt.extend([0] * (max_packets - len(splt)))
        return splt
