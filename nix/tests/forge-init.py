# Sends one kekkai handshake_init (spec §5.1, §5.5, §7.1 to §7.4) carrying an arbitrary
# certificate TLV, then waits for any reply. A kekkai node refuses to send a certificate that
# does not bind its own key (spec §4.2), so the certificates test forges that message here.
# Usage: forge-init PRIVATE_KEY RESPONDER_KEY CERTIFICATE HOST PORT (keys and certificate in
# base64). Prints "reply" and exits 0 when anything came back within 3 s, "silence" and 1
# otherwise.
import base64
import hashlib
import os
import socket
import struct
import sys
import time

from noise.connection import Keypair, NoiseConnection

private, responder, certificate = (base64.b64decode(a) for a in sys.argv[1:4])
host, port = sys.argv[4], int(sys.argv[5])

noise = NoiseConnection.from_name(b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
noise.set_as_initiator()
noise.set_psks(psk=bytes(32))
noise.set_prologue(b"kekkai\x01")
noise.set_keypair_from_private_bytes(Keypair.STATIC, private)
noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, responder)
noise.start_handshake()

now = time.time_ns()
nanos = now % 1_000_000_000
timestamp = struct.pack(
    ">QI", 0x4000_0000_0000_000A + now // 1_000_000_000, nanos - nanos % (1 << 24)
)
tlvs = struct.pack(">BH", 1, 12) + timestamp
tlvs += struct.pack(">BH", 2, len(certificate)) + certificate

message = b"\x01\x01\x00\x00" + os.urandom(4) + noise.write_message(tlvs)
mac1_key = hashlib.blake2s(b"kekkai mac1" + responder).digest()
message += hashlib.blake2s(message, key=mac1_key, digest_size=16).digest() + bytes(16)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
sock.sendto(message, (host, port))
try:
    sock.recvfrom(2048)
    print("reply")
except socket.timeout:
    print("silence")
    sys.exit(1)
