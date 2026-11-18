import zipfile, struct, sys
zin = zipfile.ZipFile(sys.argv[1])
with open(sys.argv[2], "wb") as o:
    cd = []
    for i in zin.infolist():
        raw = zin.read(i.filename)
        comp = i.compress_type
        data = raw if comp == 0 else __import__("zlib").compressobj(9, 8, -15)
        if comp != 0:
            c = data.compress(raw) + data.flush(); data = c
        import zlib
        crc = zlib.crc32(raw) & 0xffffffff
        name = i.filename.encode()
        off = o.tell()
        extra = b""
        if comp == 0:
            pad = (4 - ((off + 30 + len(name)) % 4)) % 4
            extra = b"\0" * pad
        o.write(struct.pack("<IHHHHHIIIHH", 0x04034b50, 20, 0, comp, 0, 0x21, crc, len(data), len(raw), len(name), len(extra)) + name + extra + data)
        cd.append((name, comp, crc, len(data), len(raw), off, extra))
    cds = o.tell()
    for name, comp, crc, cs, us, off, extra in cd:
        o.write(struct.pack("<IHHHHHHIIIHHHHHII", 0x02014b50, 20, 20, 0, comp, 0, 0x21, crc, cs, us, len(name), 0, 0, 0, 0, 0, off) + name)
    cde = o.tell() - cds
    o.write(struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, len(cd), len(cd), cde, cds, 0))
