import hashlib
from typing import Dict, Any, List, Optional

try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False


class TLSFingerprinter:
    @staticmethod
    def extract_ja3(payload: bytes) -> Dict[str, Any]:
        result = {
            "is_tls": False,
            "ja3_str": "",
            "ja3_hash": "",
            "sni": "",
            "cipher_count": 0,
            "tls_version": 0
        }

        if not payload or len(payload) < 5:
            return result

        if payload[0] != 0x16:  # TLS Handshake ContentType
            return result

        try:
            tls_version = int.from_bytes(payload[1:3], "big")
            handshake_type = payload[5]
            if handshake_type != 1:  # Client Hello
                return result

            result["is_tls"] = True
            result["tls_version"] = tls_version

            record = dpkt.ssl.TLS(payload)
            for msg in record.records:
                if isinstance(msg.data, dpkt.ssl.TLSClientHello):
                    ch = msg.data
                    version = str(ch.version)
                    ciphers = "-".join(str(c) for c in ch.ciphers)
                    result["cipher_count"] = len(ch.ciphers)

                    ext_types = []
                    ec_curves = []
                    ec_point_formats = []
                    sni_name = ""

                    if hasattr(ch, "extensions"):
                        for ext in ch.extensions:
                            ext_types.append(str(ext.type))
                            if ext.type == 0:  # Server Name Indication
                                try:
                                    sni_name = ext.data.decode("utf-8", errors="ignore")
                                except Exception:
                                    pass

                    extensions_str = "-".join(ext_types)
                    curves_str = "-".join(ec_curves)
                    point_formats_str = "-".join(ec_point_formats)

                    ja3_str = f"{version},{ciphers},{extensions_str},{curves_str},{point_formats_str}"
                    ja3_hash = hashlib.md5(ja3_str.encode("utf-8")).hexdigest()

                    result["ja3_str"] = ja3_str
                    result["ja3_hash"] = ja3_hash
                    result["sni"] = sni_name
                    return result
        except Exception:
            pass

        return result

    @staticmethod
    def extract_splt(packet_lengths: List[int], max_packets: int = 30) -> List[int]:
        splt = packet_lengths[:max_packets]
        if len(splt) < max_packets:
            splt.extend([0] * (max_packets - len(splt)))
        return splt
