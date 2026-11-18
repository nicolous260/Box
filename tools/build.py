#!/usr/bin/env python3
"""Assemble + sign BOX.apk (aapt2 link -> add classes.dex -> align -> APK Signature Scheme v2)."""
import os, sys, struct, zipfile, hashlib, subprocess, shutil, datetime, io
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
AAPT = "/tmp/pp/aj/package/bin/x64/linux/aapt2"
B = "build"
OUT = sys.argv[1] if len(sys.argv) > 1 else "build/BOX.apk"

def run(*a):
    subprocess.check_call(list(a))

# 1. resources -------------------------------------------------------------
shutil.rmtree(f"{B}/res", ignore_errors=True); os.makedirs(f"{B}/res")
run(AAPT, "compile", "--dir", "res", "-o", f"{B}/res/res.zip")
run(AAPT, "link", "-I", f"{B}/fw.apk", "--manifest", "AndroidManifest.xml",
    "--min-sdk-version", "24", "--target-sdk-version", "34",
    "--version-code", "1", "--version-name", "1.0",
    "-A", "assets", "-o", f"{B}/base.apk", f"{B}/res/res.zip")

# 2. dex -------------------------------------------------------------------
run(sys.executable, "tools/mkdex.py", f"{B}/classes.dex")

# 3. zip with alignment ----------------------------------------------------
DT = (2026, 11, 18, 0, 0, 0)
src = zipfile.ZipFile(f"{B}/base.apk")
entries = []   # (name, data, stored)
for it in src.infolist():
    if it.filename.endswith("/"): continue
    entries.append((it.filename, src.read(it.filename), it.filename == "resources.arsc"))
entries.append(("classes.dex", open(f"{B}/classes.dex", "rb").read(), False))
order = {"AndroidManifest.xml": 0, "resources.arsc": 2, "classes.dex": 1}
entries.sort(key=lambda e: (order.get(e[0], 3), e[0]))

buf = io.BytesIO()
zf = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9)
for name, data, stored in entries:
    zi = zipfile.ZipInfo(name, DT)
    zi.external_attr = 0o644 << 16
    zi.create_system = 0
    if stored or name.endswith((".woff2", ".png")) and False:
        zi.compress_type = zipfile.ZIP_STORED
        base = buf.tell() + 30 + len(name.encode())
        for extra_len in (0, 4, 5, 6, 7):
            if (base + extra_len) % 4 == 0 and extra_len != 1:
                break
        if extra_len:
            zi.extra = struct.pack("<HH", 0xD935, extra_len - 4) + b"\0" * (extra_len - 4)
    else:
        zi.compress_type = zipfile.ZIP_DEFLATED
    zf.writestr(zi, data)
zf.close()
apk = buf.getvalue()

# 4. APK Signature Scheme v2 -----------------------------------------------
KEY = f"{B}/box.key.pem"
if os.path.exists(KEY):
    key = serialization.load_pem_private_key(open(KEY, "rb").read(), None)
    cert = x509.load_pem_x509_certificate(open(f"{B}/box.cert.pem", "rb").read())
else:
    key = rsa.generate_private_key(65537, 2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "BOX"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "nicolous")])
    now = datetime.datetime(2026, 11, 18)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365 * 30)).sign(key, hashes.SHA256()))
    open(KEY, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    open(f"{B}/box.cert.pem", "wb").write(cert.public_bytes(serialization.Encoding.PEM))

eocd_pos = apk.rfind(b"PK\x05\x06")
cd_off = struct.unpack_from("<I", apk, eocd_pos + 16)[0]
sec1, sec3, sec4 = apk[:cd_off], apk[cd_off:eocd_pos], bytearray(apk[eocd_pos:])

CH = 1 << 20
def chunks(b):
    for i in range(0, len(b), CH):
        yield b[i:i + CH]
digs = []
for sec in (sec1, sec3, bytes(sec4)):
    for c in chunks(sec):
        digs.append(hashlib.sha256(b"\xa5" + struct.pack("<I", len(c)) + c).digest())
top = hashlib.sha256(b"\x5a" + struct.pack("<I", len(digs)) + b"".join(digs)).digest()

def lp(b): return struct.pack("<I", len(b)) + b
ALG = 0x0103  # RSASSA-PKCS1-v1_5 / SHA-256
cert_der = cert.public_bytes(serialization.Encoding.DER)
pub_der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
digest_entry = lp(struct.pack("<I", ALG) + lp(top))
signed_data = lp(digest_entry) + lp(lp(cert_der)) + lp(b"")
sig = key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
signer = lp(signed_data) + lp(lp(struct.pack("<I", ALG) + lp(sig))) + lp(pub_der)
v2_value = lp(lp(signer))
pair = struct.pack("<Q", 4 + len(v2_value)) + struct.pack("<I", 0x7109871a) + v2_value
block_size = len(pair) + 8 + 16
sigblock = struct.pack("<Q", block_size) + pair + struct.pack("<Q", block_size) + b"APK Sig Block 42"

struct.pack_into("<I", sec4, 16, cd_off + len(sigblock))
final = sec1 + sigblock + sec3 + bytes(sec4)
os.makedirs(os.path.dirname(OUT), exist_ok=True)
open(OUT, "wb").write(final)
print("wrote", OUT, len(final), "bytes")
