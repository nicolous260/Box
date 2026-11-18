import zipfile, struct, sys, os
src, out = sys.argv[1], sys.argv[2]
zin = zipfile.ZipFile(src)
items = []
for i in zin.infolist():
    if i.filename.startswith("assets/") or i.filename.startswith("META-INF/"): continue
    items.append((i.filename, zin.read(i.filename)))
for root, _, fs in os.walk("assets"):
    for f in fs:
        p = os.path.join(root, f)
        if f.startswith("LICENSE"): continue
        items.append((p, open(p, "rb").read()))
with zipfile.ZipFile(out, "w") as z:
    for n, d in items:
        z.writestr(n, d, compress_type=zipfile.ZIP_STORED if n.endswith((".arsc", ".woff2", ".png")) else zipfile.ZIP_DEFLATED)
print(len(items), "entries")
