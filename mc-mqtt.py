import hashlib
import hmac as hmac_mod
import struct
import math
import time
import datetime
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------------------------------------------------------------------
# Known channels  (16-byte hex PSK keys as given by the firmware/app UI)
# ---------------------------------------------------------------------------

def _build_channel(name: str, key_hex: str) -> dict:
    key     = bytes.fromhex(key_hex)
    assert len(key) == 16, f"Channel key must be 16 bytes: {name}"
    ch_hash = hashlib.sha256(key).digest()[0]
    secret  = key.ljust(32, b'\x00')   # 32-byte key for HMAC
    return {"name": name, "key": key, "hash": ch_hash, "secret": secret}

KNOWN_CHANNELS = [
    _build_channel("Public",     "8b3387e9c5cdea6ac9e5edbaa115cd72"),
    _build_channel("#test",      "9cd8fcf22a47333b591d96a2b848b73f"),
]

# name -> channel dict  (for sending)
CHANNEL_BY_NAME: dict[str, dict] = {ch["name"]: ch for ch in KNOWN_CHANNELS}

# hash byte -> list of channels  (for receiving; hash collisions are possible)
CHANNEL_BY_HASH: dict[int, list[dict]] = {}
for _ch in KNOWN_CHANNELS:
    CHANNEL_BY_HASH.setdefault(_ch["hash"], []).append(_ch)

print("Known channel hashes:")
for ch in KNOWN_CHANNELS:
    print(f"  0x{ch['hash']:02x}  {ch['name']}")
print()

# ---------------------------------------------------------------------------
# Packet field maps
# ---------------------------------------------------------------------------

ROUTE_TYPES = {
    0: "TRANSPORT_FLOOD",
    1: "FLOOD",
    2: "DIRECT",
    3: "TRANSPORT_DIRECT",
}

PAYLOAD_TYPES = {
    0:  "REQ",
    1:  "RESPONSE",
    2:  "TXT_MSG",
    3:  "ACK",
    4:  "ADVERT",
    5:  "GRP_TXT",
    6:  "GRP_DATA",
    7:  "ANON_REQ",
    8:  "PATH",
    9:  "TRACE",
    10: "MULTIPART",
    11: "CONTROL",
    15: "RAW_CUSTOM",
}

# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def _compute_mac(secret: bytes, ciphertext: bytes) -> bytes:
    """HMAC-SHA256 truncated to 2 bytes, keyed with the 32-byte secret."""
    return hmac_mod.new(secret, ciphertext, hashlib.sha256).digest()[:2]


def _verify_mac(secret: bytes, ciphertext: bytes, mac: bytes) -> bool:
    return _compute_mac(secret, ciphertext) == mac


def _encrypt_aes_ecb(key16: bytes, plaintext: bytes) -> bytes:
    """AES-128-ECB encrypt. Plaintext must already be padded to 16-byte blocks."""
    cipher = Cipher(algorithms.AES(key16), modes.ECB())
    return cipher.encryptor().update(plaintext)


def _decrypt_aes_ecb(key16: bytes, ciphertext: bytes) -> bytes:
    """AES-128-ECB decrypt."""
    cipher = Cipher(algorithms.AES(key16), modes.ECB())
    return cipher.decryptor().update(ciphertext)


def _pad16(data: bytes) -> bytes:
    """Zero-pad to the next multiple of 16 bytes."""
    pad_len = math.ceil(len(data) / 16) * 16
    return data.ljust(pad_len, b'\x00')


# ---------------------------------------------------------------------------
# Packet builder  (GRP_TXT, FLOOD, no path hops)
# ---------------------------------------------------------------------------

def build_grp_txt_packet(
    channel_name: str,
    sender_name:  str,
    message:      str,
    attempt:      int = 0,
    timestamp:    int | None = None,
) -> bytes:
    """
    Build a complete MeshCore GRP_TXT packet ready to publish on MQTT.

    Layout:
      [header:1]        0x15  =  ver(0)<<6 | GRP_TXT(5)<<2 | FLOOD(1)
      [path_len:1]      0x00  =  0 hops, hash_size=1  (bits: 00_000000)
      [channel_hash:1]        first byte of sha256(channel_key)
      [mac:2]                 hmac-sha256(32-byte-secret, ciphertext)[:2]
      [ciphertext:N]          AES-128-ECB( zero-padded( timestamp+flags+text ) )

    Plaintext inside ciphertext:
      [timestamp:4 LE]        unix epoch
      [flags:1]               (msg_type<<2) | attempt  — plain text = 0
      [text]                  "sender_name: message"   zero-padded to 16B block
    """
    ch = CHANNEL_BY_NAME.get(channel_name)
    if ch is None:
        raise ValueError(
            f"Unknown channel '{channel_name}'. "
            f"Known: {list(CHANNEL_BY_NAME.keys())}"
        )

    if timestamp is None:
        timestamp = int(time.time())

    flags     = (0 << 2) | (attempt & 0x03)   # msg_type=0 (plain text)
    text      = f"{sender_name}: {message}"
    raw_plain = struct.pack('<I', timestamp) + bytes([flags]) + text.encode('utf-8')
    plaintext = _pad16(raw_plain)

    ciphertext = _encrypt_aes_ecb(ch["key"], plaintext)
    mac        = _compute_mac(ch["secret"], ciphertext)

    # header: ver=0, ptype=GRP_TXT(5), route=FLOOD(1)
    header         = (0 << 6) | (5 << 2) | 1   # 0x15
    path_len_byte  = 0x00                        # hash_size bits=00→1B, count=0

    packet = bytes([header, path_len_byte, ch["hash"]]) + mac + ciphertext
    return packet


# ---------------------------------------------------------------------------
# Packet decoder  (receive path, unchanged from previous version)
# ---------------------------------------------------------------------------

def _try_decrypt_group(channel_hash_byte: int, mac: bytes, ciphertext: bytes) -> dict | None:
    candidates = CHANNEL_BY_HASH.get(channel_hash_byte, [])
    for ch in candidates:
        if not _verify_mac(ch["secret"], ciphertext, mac):
            continue
        plaintext = _decrypt_aes_ecb(ch["key"], ciphertext)
        if len(plaintext) < 5:
            continue
        timestamp = struct.unpack('<I', plaintext[:4])[0]
        flags     = plaintext[4]
        msg_type  = (flags >> 2) & 0x3F
        attempt   = flags & 0x03
        text_raw  = plaintext[5:].rstrip(b'\x00')
        try:
            text = text_raw.decode('utf-8')
        except UnicodeDecodeError:
            text = text_raw.decode('latin-1')
        dt = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)
        return {
            "channel":   ch["name"],
            "timestamp": timestamp,
            "datetime":  dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "flags":     flags,
            "msg_type":  msg_type,
            "attempt":   attempt,
            "text":      text,
        }
    return None


def decode_packet(data: bytes) -> dict:
    """Decode a raw MeshCore packet published on the MQTT bridge topic."""
    if len(data) < 2:
        return {"error": "too short", "raw": data.hex()}

    header = data[0]
    route  = header & 0x03
    ptype  = (header >> 2) & 0x0F
    ver    = (header >> 6) & 0x03

    idx = 1
    transport_codes = None
    if route in (0, 3):
        if len(data) < idx + 4:
            return {"error": "truncated (transport codes)", "raw": data.hex()}
        tc1 = int.from_bytes(data[idx:idx + 2], "little")
        tc2 = int.from_bytes(data[idx + 2:idx + 4], "little")
        transport_codes = (tc1, tc2)
        idx += 4

    if len(data) < idx + 1:
        return {"error": "truncated (path_len)", "raw": data.hex()}

    path_len_byte = data[idx]
    idx += 1
    hash_size  = (path_len_byte >> 6) + 1
    hash_count = path_len_byte & 0x3F

    if hash_size == 4:
        return {"error": "invalid path hash size (reserved)", "raw": data.hex()}

    path_bytes_len = hash_size * hash_count
    if len(data) < idx + path_bytes_len:
        return {"error": "truncated (path)", "raw": data.hex()}

    path = data[idx:idx + path_bytes_len]
    idx += path_bytes_len
    payload = data[idx:]

    result = {
        "raw":             data.hex(),
        "total_len":       len(data),
        "header_byte":     header,
        "route_type":      ROUTE_TYPES.get(route, f"unknown({route})"),
        "payload_type":    PAYLOAD_TYPES.get(ptype, f"unknown({ptype})"),
        "payload_ver":     ver,
        "path_hash_size":  hash_size,
        "path_hash_count": hash_count,
        "path":            path.hex(),
        "payload_len":     len(payload),
        "payload":         payload.hex(),
    }
    if transport_codes is not None:
        result["transport_codes"] = transport_codes

    if ptype in (5, 6):  # GRP_TXT / GRP_DATA
        if len(payload) >= 3:
            ch_hash    = payload[0]
            mac        = payload[1:3]
            ciphertext = payload[3:]
            result["channel_hash"] = f"{ch_hash:02x}"
            result["mac"]          = mac.hex()
            result["ciphertext"]   = ciphertext.hex()
            decrypted = _try_decrypt_group(ch_hash, mac, ciphertext)
            result["decrypted"] = decrypted  # None if unknown/MAC fail

    elif ptype in (0, 1, 2, 8):
        if len(payload) >= 4:
            result["dest_hash"]  = f"{payload[0]:02x}"
            result["src_hash"]   = f"{payload[1]:02x}"
            result["mac"]        = payload[2:4].hex()
            result["ciphertext"] = payload[4:].hex()

    elif ptype == 7:
        if len(payload) >= 1:
            result["dest_hash"] = f"{payload[0]:02x}"
            result["ephemeral_pubkey_mac_ciphertext"] = payload[1:].hex()

    elif ptype == 4:
        if len(payload) >= 1:
            result["node_hash"]   = f"{payload[0]:02x}"
            result["advert_data"] = payload[1:].hex()

    return result


# ---------------------------------------------------------------------------
# Pretty printer
# ---------------------------------------------------------------------------

def format_packet(result: dict) -> str:
    if "error" in result:
        return f"  [decode error: {result['error']}] raw={result['raw']}"

    lines = []
    lines.append(f"  total_len      : {result['total_len']} bytes")
    lines.append(f"  header_byte    : 0x{result['header_byte']:02x}")
    lines.append(f"  route_type     : {result['route_type']}")
    lines.append(f"  payload_type   : {result['payload_type']} (ver {result['payload_ver']})")
    if "transport_codes" in result:
        lines.append(f"  transport_codes: {result['transport_codes']}")
    lines.append(
        f"  path           : {result['path_hash_count']} hop(s), "
        f"{result['path_hash_size']}B hash -> {result['path'] or '(empty)'}"
    )
    lines.append(f"  payload ({result['payload_len']}B) : {result['payload']}")

    if "channel_hash" in result:
        lines.append(f"    channel_hash : 0x{result['channel_hash']}")
        lines.append(f"    mac          : {result['mac']}")
        lines.append(f"    ciphertext   : {result['ciphertext']}")
        dec = result.get("decrypted")
        if dec:
            lines.append(f"    ── DECRYPTED ──────────────────────────────")
            lines.append(f"    channel      : {dec['channel']}")
            lines.append(f"    time         : {dec['datetime']} (unix {dec['timestamp']})")
            lines.append(f"    msg_type     : {dec['msg_type']}  attempt: {dec['attempt']}")
            lines.append(f"    text         : {dec['text']}")
            lines.append(f"    ───────────────────────────────────────────")
        else:
            lines.append(f"    [unknown channel or MAC mismatch — cannot decrypt]")

    elif "dest_hash" in result and "src_hash" in result:
        lines.append(f"    dest_hash    : 0x{result['dest_hash']}")
        lines.append(f"    src_hash     : 0x{result['src_hash']}")
        lines.append(f"    mac          : {result['mac']}")
        lines.append(f"    ciphertext   : {result['ciphertext']}")
    elif "dest_hash" in result and "ephemeral_pubkey_mac_ciphertext" in result:
        lines.append(f"    dest_hash    : 0x{result['dest_hash']}")
        lines.append(f"    eph.pubkey+mac+ct: {result['ephemeral_pubkey_mac_ciphertext']}")
    elif "node_hash" in result:
        lines.append(f"    node_hash    : 0x{result['node_hash']}")
        lines.append(f"    advert_data  : {result['advert_data']}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Send helper
# ---------------------------------------------------------------------------

def send_grp_txt(
    mqtt_client:  mqtt.Client,
    topic:        str,
    channel_name: str,
    sender_name:  str,
    message:      str,
) -> None:
    """Encode and publish a GRP_TXT packet to the given MQTT topic."""
    packet = build_grp_txt_packet(channel_name, sender_name, message)
    mqtt_client.publish(topic, packet)
    print(f"\n[SENT → {topic}]  channel={channel_name}  "
          f"sender={sender_name!r}  msg={message!r}")
    print(f"  packet ({len(packet)}B): {packet.hex()}")


# ---------------------------------------------------------------------------
# MQTT callbacks
# ---------------------------------------------------------------------------
MQTT_TOPIC = "testing"


def on_connect(client, userdata, flags, rc):
    print("Connected with result code", rc)
    client.subscribe(MQTT_TOPIC)

    # -----------------------------------------------------------------------
    # Example: send "Example world" to #test right after connecting
    # -----------------------------------------------------------------------
    send_grp_txt(client, MQTT_TOPIC, "#test", "PythonBridge", "Example world")


def on_message(client, userdata, msg):
    raw = msg.payload
    print(f"\n[{msg.topic}] {len(raw)} bytes: {raw.hex()}")
    decoded = decode_packet(raw)
    print(format_packet(decoded))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.connect("192.168.123.123", 1883, 60)
client.loop_forever()
