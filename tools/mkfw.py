#!/usr/bin/env python3
"""Build a stub 'android' framework resource APK (package id 0x01) for aapt2 -I.
aapt2 refuses --package-id 0x01, so link as 0x02 and rewrite ids to 0x01."""
import struct, sys, zipfile, subprocess, os, shutil

AAPT = sys.argv[1]; OUT = sys.argv[2]; WORK = sys.argv[3]
os.makedirs(WORK, exist_ok=True)
subprocess.check_call([AAPT, "compile", "--dir", "fw/res", "-o", f"{WORK}/res.zip"])
subprocess.check_call([AAPT, "link", "--package-id", "0x02", "--allow-reserved-package-id",
                       "--manifest", "fw/AndroidManifest.xml",
                       "-o", f"{WORK}/fw02.apk", f"{WORK}/res.zip"])

FROM, TO = 0x02, 0x01
def fix(v):
    return (v & 0x00ffffff) | (TO << 24) if (v >> 24) == FROM else v

def patch_arsc(b):
    b = bytearray(b)
    u16 = lambda o: struct.unpack_from("<H", b, o)[0]
    u32 = lambda o: struct.unpack_from("<I", b, o)[0]
    def put32(o, v): struct.pack_into("<I", b, o, v)
    tsize = u32(4)
    off = u16(2)
    n = 0
    while off < tsize:
        ctype, chdr, csize = u16(off), u16(off + 2), u32(off + 4)
        if ctype == 0x0200:  # package
            assert u32(off + 8) == FROM
            put32(off + 8, TO); n += 1
            nm = "android".encode("utf-16-le").ljust(256, b"\0")
            b[off + 12: off + 12 + 256] = nm
            p = off + chdr
            pend = off + csize
            while p < pend:
                t, h, s = u16(p), u16(p + 2), u32(p + 4)
                if t == 0x0201:  # type
                    cnt = u32(p + 12); estart = u32(p + 16)
                    flags = b[p + 9]
                    assert not (flags & 1), "sparse not handled"
                    offs = [u32(p + h + 4 * i) for i in range(cnt)]
                    for eo in offs:
                        if eo == 0xffffffff: continue
                        e = p + estart + eo
                        esize, eflags = u16(e), u16(e + 2)
                        if eflags & 1:
                            par = u32(e + 8); put32(e + 8, fix(par))
                            mc = u32(e + 12)
                            q = e + 16
                            for _ in range(mc):
                                put32(q, fix(u32(q)))
                                if b[q + 7] in (1, 2):
                                    put32(q + 8, fix(u32(q + 8))); n += 1
                                q += 12
                        else:
                            v = e + esize
                            if b[v + 3] in (1, 2): put32(v + 4, fix(u32(v + 4))); n += 1
                p += s
        off += csize
    return bytes(b), n

zin = zipfile.ZipFile(f"{WORK}/fw02.apk")
with zipfile.ZipFile(OUT, "w") as zo:
    for it in zin.infolist():
        data = zin.read(it.filename)
        if it.filename == "resources.arsc":
            data, n = patch_arsc(data)
            print("patched arsc, touched", n)
        zo.writestr(it, data)
print("wrote", OUT)
