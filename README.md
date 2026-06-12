**Simple POC for communctaion MQTT<->Meshcore network.**
\
\
Example output during running console is:\
\
[MQTT Topic] 89 bytes: *Redacted Data*\
  total_len      : 89 bytes\
  header_byte    : 0x15\
  route_type     : FLOOD\
  payload_type   : GRP_TXT (ver 0)\
  path           : 10 hop(s), 2B hash -> *Redacted Data*\
  payload (67B) : *Redacted Data*\
    channel_hash : 0x11\
    mac          : 0840\
    ciphertext   : *Redacted Data*\
    ── DECRYPTED ──────────────────────────────\
    channel      : Public\
    time         : 2026-06-12 01:02:03 UTC\
    msg_type     : 0  attempt: 0\
    text         : Username: Message Content\
    ───────────────────────────────────────────




If data are not decrypted due to missing keys, then decypted segment is not printed.
