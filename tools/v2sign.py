import sys, struct, hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
src, out, keyf, certf = sys.argv[1:5]
d = open(src, "rb").read()
eocd = d.rindex(b"PK\x05\x06")
cdoff, = struct.unpack("<I", d[eocd+16:eocd+20])
secs = [d[:cdoff], d[cdoff:eocd], d[eocd:]]
# EOCD cd offset treated as pointing at signing block start == cdoff (unchanged)
def chunks(b):
    for i in range(0, len(b), 1<<20): yield b[i:i+(1<<20)]
dg = []
for s in secs:
    for c in chunks(s):
        dg.append(hashlib.sha256(b"\xa5" + struct.pack("<I", len(c)) + c).digest())
top = hashlib.sha256(b"\x5a" + struct.pack("<I", len(dg)) + b"".join(dg)).digest()
key = serialization.load_pem_private_key(open(keyf,"rb").read(), None)
cert = x509.load_pem_x509_certificate(open(certf,"rb").read()).public_bytes(serialization.Encoding.DER)
L = lambda b: struct.pack("<I", len(b)) + b
ALGO = 0x0103  # RSASSA-PKCS1-v1_5 with SHA2-256
digests = L(struct.pack("<I", ALGO) + L(top))
signed = L(digests) + L(L(cert)) + L(b"")
sig = key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
pub = x509.load_pem_x509_certificate(open(certf,"rb").read()).public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
signer = L(signed) + L(L(struct.pack("<I", ALGO) + L(sig))) + L(pub)
v2 = L(L(signer))
pair = struct.pack("<Q", len(v2)+4) + struct.pack("<I", 0x7109871a) + v2
blk = struct.pack("<Q", len(pair)+8+16) + pair + struct.pack("<Q", len(pair)+8+16) + b"APK Sig Block 42"
neweocd = bytearray(secs[2]); neweocd[16:20] = struct.pack("<I", cdoff + len(blk))
open(out, "wb").write(secs[0] + blk + secs[1] + bytes(neweocd))
