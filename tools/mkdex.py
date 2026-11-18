#!/usr/bin/env python3
"""Tiny DEX (v035) writer: hand-assembles a WebView host Activity.

Classes produced:
  com.nicolous.box.MainActivity  extends Activity   (WebView host, back handling)
  com.nicolous.box.Bridge                           (@JavascriptInterface: bars(), share())
  com.nicolous.box.Bars          implements Runnable (sets status/nav bar colours on UI thread)
"""
import struct, hashlib, zlib, sys

PKG = "com/nicolous/box/"

def uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)

def mutf8(s):
    out = bytearray()
    for ch in s:
        c = ord(ch)
        if c == 0:
            out += b"\xc0\x80"
        elif c < 0x80:
            out.append(c)
        elif c < 0x800:
            out += bytes([0xc0 | (c >> 6), 0x80 | (c & 0x3f)])
        else:
            out += bytes([0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f)])
    return bytes(out)

# ---------------------------------------------------------------- symbolic refs
class M:  # method ref
    def __init__(s, cls, name, ret, params=()):
        s.cls, s.name, s.ret, s.params = cls, name, ret, tuple(params)
    def key(s): return (s.cls, s.name, s.ret, s.params)

class F:  # field ref
    def __init__(s, cls, name, typ):
        s.cls, s.name, s.typ = cls, name, typ

def T(name):  # object descriptor
    return "L" + name + ";"

ACT = T("android/app/Activity")
BUNDLE = T("android/os/Bundle")
VIEW = T("android/view/View")
WINDOW = T("android/view/Window")
CTX = T("android/content/Context")
INTENT = T("android/content/Intent")
WV = T("android/webkit/WebView")
WS = T("android/webkit/WebSettings")
WVC = T("android/webkit/WebViewClient")
STR = T("java/lang/String")
OBJ = T("java/lang/Object")
CHARSEQ = T("java/lang/CharSequence")
RUNN = T("java/lang/Runnable")
JSI = T("android/webkit/JavascriptInterface")
MAIN = T(PKG + "MainActivity")
BRIDGE = T(PKG + "Bridge")
BARS = T(PKG + "Bars")

# ---------------------------------------------------------------- instructions
OPS = dict(
    const4=0x12, const16=0x13, const=0x14, consthigh16=0x15, conststring=0x1a,
    newinstance=0x22, movresult=0x0a, movresultobj=0x0c, retvoid=0x0e,
    ifeqz=0x38, goto=0x28,
    iget=0x52, igetobj=0x54, igetbool=0x55,
    iput=0x59, iputobj=0x5b, iputbool=0x5c,
    invvirt=0x6e, invsuper=0x6f, invdirect=0x70, invstatic=0x71,
)

class I:
    def __init__(s, op, *a, label=None, target=None):
        s.op, s.a, s.label, s.target = op, a, label, target
        s.size = {
            "const4": 1, "const16": 2, "consthigh16": 2, "conststring": 2,
            "newinstance": 2, "movresult": 1, "movresultobj": 1, "retvoid": 1,
            "ifeqz": 2, "goto": 1, "iget": 2, "igetobj": 2, "igetbool": 2,
            "iput": 2, "iputobj": 2, "iputbool": 2,
            "invvirt": 3, "invsuper": 3, "invdirect": 3, "invstatic": 3,
        }[op]
        s.pc = 0

def assemble(code, ctx):
    pc = 0
    labels = {}
    for ins in code:
        ins.pc = pc
        if ins.label:
            labels[ins.label] = pc
        pc += ins.size
    out = []
    for ins in code:
        op = OPS[ins.op]
        a = ins.a
        k = ins.op
        if k in ("invvirt", "invsuper", "invdirect", "invstatic"):
            regs, mref = a
            idx = ctx.method_idx(mref)
            n = len(regs)
            r = list(regs) + [0] * (5 - n)
            out += [op | (r[4] << 8) | (n << 12), idx,
                    r[0] | (r[1] << 4) | (r[2] << 8) | (r[3] << 12)]
        elif k in ("newinstance",):
            out += [op | (a[0] << 8), ctx.type_idx(a[1])]
        elif k == "conststring":
            out += [op | (a[0] << 8), ctx.string_idx(a[1])]
        elif k in ("iget", "igetobj", "igetbool", "iput", "iputobj", "iputbool"):
            va, vb, fref = a
            out += [op | (va << 8) | (vb << 12), ctx.field_idx(fref)]
        elif k in ("movresult", "movresultobj"):
            out += [op | (a[0] << 8)]
        elif k == "const4":
            out += [op | (a[0] << 8) | ((a[1] & 0xf) << 12)]
        elif k == "const16":
            out += [op | (a[0] << 8), a[1] & 0xffff]
        elif k == "consthigh16":
            out += [op | (a[0] << 8), (a[1] >> 16) & 0xffff]
        elif k == "retvoid":
            out += [op]
        elif k == "ifeqz":
            off = labels[ins.target] - ins.pc
            out += [op | (a[0] << 8), off & 0xffff]
        elif k == "goto":
            off = labels[ins.target] - ins.pc
            assert -128 <= off <= 127
            out += [op | ((off & 0xff) << 8)]
        else:
            raise ValueError(k)
    assert len(out) == pc, (len(out), pc)
    return out

# ---------------------------------------------------------------- class model
class Method:
    def __init__(s, ref, flags, regs, ins, outs, code, annot=None):
        s.ref, s.flags, s.regs, s.ins, s.outs, s.code, s.annot = ref, flags, regs, ins, outs, code, annot

class Cls:
    def __init__(s, desc, flags, sup, interfaces=(), fields=(), direct=(), virtual=()):
        s.desc, s.flags, s.sup = desc, flags, sup
        s.interfaces = tuple(interfaces)
        s.fields = list(fields)   # (F, flags)
        s.direct, s.virtual = list(direct), list(virtual)

PUB, PRIV, FINAL, CTOR = 0x1, 0x2, 0x10, 0x10000
ACC_PUBLIC_CTOR = PUB | CTOR

f_web = F(MAIN, "web", WV)
f_act = F(BRIDGE, "act", ACT)
f_bact = F(BARS, "act", ACT)
f_bcolor = F(BARS, "color", "I")
f_blight = F(BARS, "light", "Z")

def build_classes():
    obj_init = M(OBJ, "<init>", "V")
    act_init = M(ACT, "<init>", "V")

    # ---- MainActivity
    ctor = Method(M(MAIN, "<init>", "V"), ACC_PUBLIC_CTOR, 1, 1, 1, [
        I("invdirect", [0], act_init),
        I("retvoid"),
    ])
    oncreate = Method(M(MAIN, "onCreate", "V", [BUNDLE]), PUB, 5, 2, 3, [
        I("invsuper", [3, 4], M(ACT, "onCreate", "V", [BUNDLE])),
        I("newinstance", 0, WV),
        I("invdirect", [0, 3], M(WV, "<init>", "V", [CTX])),
        I("iputobj", 0, 3, f_web),
        I("invvirt", [0], M(WV, "getSettings", WS)),
        I("movresultobj", 1),
        I("const4", 2, 1),
        I("invvirt", [1, 2], M(WS, "setJavaScriptEnabled", "V", ["Z"])),
        I("invvirt", [1, 2], M(WS, "setDomStorageEnabled", "V", ["Z"])),
        I("invvirt", [1, 2], M(WS, "setMediaPlaybackRequiresUserGesture", "V", ["Z"])),
        I("newinstance", 1, WVC),
        I("invdirect", [1], M(WVC, "<init>", "V")),
        I("invvirt", [0, 1], M(WV, "setWebViewClient", "V", [WVC])),
        I("newinstance", 1, BRIDGE),
        I("invdirect", [1, 3], M(BRIDGE, "<init>", "V", [ACT])),
        I("conststring", 2, "Android"),
        I("invvirt", [0, 1, 2], M(WV, "addJavascriptInterface", "V", [OBJ, STR])),
        I("conststring", 1, "file:///android_asset/index.html"),
        I("invvirt", [0, 1], M(WV, "loadUrl", "V", [STR])),
        I("invvirt", [3, 0], M(ACT, "setContentView", "V", [VIEW])),
        I("retvoid"),
    ])
    onback = Method(M(MAIN, "onBackPressed", "V"), PUB, 3, 1, 1, [
        I("igetobj", 0, 2, f_web),
        I("invvirt", [0], M(WV, "canGoBack", "Z")),
        I("movresult", 1),
        I("ifeqz", 1, target="fin"),
        I("invvirt", [0], M(WV, "goBack", "V")),
        I("retvoid"),
        I("invsuper", [2], M(ACT, "onBackPressed", "V"), label="fin"),
        I("retvoid"),
    ])
    main = Cls(MAIN, PUB, ACT, fields=[(f_web, PRIV)], direct=[ctor], virtual=[oncreate, onback])

    # ---- Bridge
    bctor = Method(M(BRIDGE, "<init>", "V", [ACT]), ACC_PUBLIC_CTOR, 2, 2, 1, [
        I("invdirect", [0], obj_init),
        I("iputobj", 1, 0, f_act),
        I("retvoid"),
    ])
    bars = Method(M(BRIDGE, "bars", "V", ["I", "Z"]), PUB, 5, 3, 4, [
        I("newinstance", 0, BARS),
        I("igetobj", 1, 2, f_act),
        I("invdirect", [0, 1, 3, 4], M(BARS, "<init>", "V", [ACT, "I", "Z"])),
        I("invvirt", [1, 0], M(ACT, "runOnUiThread", "V", [RUNN])),
        I("retvoid"),
    ], annot=JSI)
    share = Method(M(BRIDGE, "share", "V", [STR]), PUB, 4, 2, 3, [
        I("newinstance", 0, INTENT),
        I("conststring", 1, "android.intent.action.SEND"),
        I("invdirect", [0, 1], M(INTENT, "<init>", "V", [STR])),
        I("conststring", 1, "text/plain"),
        I("invvirt", [0, 1], M(INTENT, "setType", INTENT, [STR])),
        I("conststring", 1, "android.intent.extra.TEXT"),
        I("invvirt", [0, 1, 3], M(INTENT, "putExtra", INTENT, [STR, STR])),
        I("const4", 1, 0),
        I("invstatic", [0, 1], M(INTENT, "createChooser", INTENT, [INTENT, CHARSEQ])),
        I("movresultobj", 0),
        I("igetobj", 1, 2, f_act),
        I("invvirt", [1, 0], M(ACT, "startActivity", "V", [INTENT])),
        I("retvoid"),
    ], annot=JSI)
    bridge = Cls(BRIDGE, PUB, OBJ, fields=[(f_act, PRIV)], direct=[bctor], virtual=[bars, share])

    # ---- Bars (Runnable)
    kctor = Method(M(BARS, "<init>", "V", [ACT, "I", "Z"]), ACC_PUBLIC_CTOR, 4, 4, 1, [
        I("invdirect", [0], obj_init),
        I("iputobj", 1, 0, f_bact),
        I("iput", 2, 0, f_bcolor),
        I("iputbool", 3, 0, f_blight),
        I("retvoid"),
    ])
    run = Method(M(BARS, "run", "V"), PUB, 4, 1, 2, [
        I("igetobj", 0, 3, f_bact),
        I("invvirt", [0], M(ACT, "getWindow", WINDOW)),
        I("movresultobj", 0),
        I("consthigh16", 2, 0x80000000),
        I("invvirt", [0, 2], M(WINDOW, "addFlags", "V", ["I"])),
        I("iget", 1, 3, f_bcolor),
        I("invvirt", [0, 1], M(WINDOW, "setStatusBarColor", "V", ["I"])),
        I("invvirt", [0, 1], M(WINDOW, "setNavigationBarColor", "V", ["I"])),
        I("invvirt", [0], M(WINDOW, "getDecorView", VIEW)),
        I("movresultobj", 0),
        I("igetbool", 1, 3, f_blight),
        I("ifeqz", 1, target="dark"),
        I("const16", 1, 0x2010),
        I("goto", target="set"),
        I("const4", 1, 0, label="dark"),
        I("invvirt", [0, 1], M(VIEW, "setSystemUiVisibility", "V", ["I"]), label="set"),
        I("retvoid"),
    ])
    barsc = Cls(BARS, PUB | FINAL, OBJ, interfaces=[RUNN],
                fields=[(f_bact, PRIV | FINAL), (f_bcolor, PRIV | FINAL), (f_blight, PRIV | FINAL)],
                direct=[kctor], virtual=[run])
    return [main, bridge, barsc]

# ---------------------------------------------------------------- writer
def shorty_char(d):
    return "L" if d[0] in "L[" else d

class Ctx:
    pass

def build_dex(classes):
    c = Ctx()
    strings, types, protos, fields, methods = set(), set(), set(), set(), set()

    def add_type(t):
        types.add(t); strings.add(t)

    def add_method(m):
        add_type(m.cls); add_type(m.ret)
        for p in m.params: add_type(p)
        strings.add(m.name)
        sh = shorty_char(m.ret) + "".join(shorty_char(p) for p in m.params)
        strings.add(sh)
        protos.add((m.ret, m.params))
        methods.add(m.key())

    def add_field(f):
        add_type(f.cls); add_type(f.typ); strings.add(f.name)
        fields.add((f.cls, f.name, f.typ))

    # first pass: collect (including from code)
    from_code_strings = set()
    for cl in classes:
        add_type(cl.desc); add_type(cl.sup)
        for i in cl.interfaces: add_type(i)
        for f, _ in cl.fields: add_field(f)
        for m in cl.direct + cl.virtual:
            add_method(m.ref)
            if m.annot: add_type(m.annot)
            for ins in m.code:
                for a in ins.a:
                    if isinstance(a, M): add_method(a)
                    elif isinstance(a, F): add_field(a)
                    elif isinstance(a, tuple) or isinstance(a, list): pass
                if ins.op in ("invvirt", "invsuper", "invdirect", "invstatic"):
                    add_method(ins.a[1])
                if ins.op == "newinstance": add_type(ins.a[1])
                if ins.op == "conststring": strings.add(ins.a[1])
                if ins.op in ("iget", "igetobj", "igetbool", "iput", "iputobj", "iputbool"): add_field(ins.a[2])

    S = sorted(strings, key=lambda s: s.encode("utf-16-be"))
    sidx = {s: i for i, s in enumerate(S)}
    TY = sorted(types, key=lambda t: sidx[t])
    tidx = {t: i for i, t in enumerate(TY)}

    def shorty(p):
        return shorty_char(p[0]) + "".join(shorty_char(x) for x in p[1])
    PR = sorted(protos, key=lambda p: (tidx[p[0]], tuple(tidx[x] for x in p[1])))
    pidx = {p: i for i, p in enumerate(PR)}
    FL = sorted(fields, key=lambda f: (tidx[f[0]], sidx[f[1]], tidx[f[2]]))
    fidx = {f: i for i, f in enumerate(FL)}
    ML = sorted(methods, key=lambda m: (tidx[m[0]], sidx[m[1]], pidx[(m[2], m[3])]))
    midx = {m: i for i, m in enumerate(ML)}

    c.string_idx = lambda s: sidx[s]
    c.type_idx = lambda t: tidx[t]
    c.field_idx = lambda f: fidx[(f.cls, f.name, f.typ)]
    c.method_idx = lambda m: midx[m.key()]

    # sections
    hdr_size = 0x70
    off = hdr_size
    string_ids_off = off; off += 4 * len(S)
    type_ids_off = off; off += 4 * len(TY)
    proto_ids_off = off; off += 12 * len(PR)
    field_ids_off = off; off += 8 * len(FL)
    method_ids_off = off; off += 8 * len(ML)
    class_defs_off = off; off += 32 * len(classes)
    data_off = off

    data = bytearray()
    def align(n):
        while (data_off + len(data)) % n: data.append(0)
    def here(): return data_off + len(data)
    map_entries = []  # (type, count, offset)

    # type lists
    tl_off = {}
    tls = set()
    for p in PR:
        if p[1]: tls.add(p[1])
    for cl in classes:
        if cl.interfaces: tls.add(cl.interfaces)
    tl_sorted = sorted(tls, key=lambda t: tuple(tidx[x] for x in t))
    if tl_sorted:
        align(4); start = here()
        for tl in tl_sorted:
            align(4)
            tl_off[tl] = here()
            data += struct.pack("<I", len(tl))
            for t in tl: data += struct.pack("<H", tidx[t])
        map_entries.append((0x1001, len(tl_sorted), start))

    # annotation items + sets
    annot_item_off, annot_set_off = {}, {}
    annot_types = sorted({m.annot for cl in classes for m in cl.direct + cl.virtual if m.annot})
    # annotation_set_item (aligned 4) -- one set per annotation type used
    if annot_types:
        align(4); start = here()
        # annotation items are byte aligned and come later; sets reference them so reserve: write items first
        pass
    # write annotation_items first (byte aligned)
    ai_start = None
    for at in annot_types:
        if ai_start is None: ai_start = here()
        annot_item_off[at] = here()
        data += bytes([1]) + uleb(tidx[at]) + uleb(0)   # visibility RUNTIME, no elements
    if annot_types:
        map_entries.append((0x2004, len(annot_types), ai_start))
        align(4); sstart = here()
        for at in annot_types:
            align(4)
            annot_set_off[at] = here()
            data += struct.pack("<II", 1, annot_item_off[at])
        map_entries.append((0x1003, len(annot_types), sstart))

    # code items
    code_off = {}
    ci_start = None; ci_count = 0
    for cl in classes:
        for m in cl.direct + cl.virtual:
            insns = assemble(m.code, c)
            align(4)
            if ci_start is None: ci_start = here()
            code_off[m.ref.key()] = here()
            data += struct.pack("<HHHHII", m.regs, m.ins, m.outs, 0, 0, len(insns))
            data += b"".join(struct.pack("<H", u) for u in insns)
            ci_count += 1
    map_entries.append((0x2001, ci_count, ci_start))

    # annotations directories (one per class that has annotated methods)
    ad_off = {}
    ad_start = None; ad_count = 0
    for cl in classes:
        am = [(c.method_idx(m.ref), annot_set_off[m.annot]) for m in cl.direct + cl.virtual if m.annot]
        if am:
            align(4)
            if ad_start is None: ad_start = here()
            ad_off[cl.desc] = here()
            am.sort()
            data += struct.pack("<IIII", 0, 0, len(am), 0)
            for mi, so in am: data += struct.pack("<II", mi, so)
            ad_count += 1
    if ad_count: map_entries.append((0x2006, ad_count, ad_start))

    # class data
    cd_off = {}
    cd_start = None
    for cl in classes:
        if cd_start is None: cd_start = here()
        cd_off[cl.desc] = here()
        flds = sorted(((c.field_idx(f), fl) for f, fl in cl.fields))
        dm = sorted(((c.method_idx(m.ref), m) for m in cl.direct), key=lambda x: x[0])
        vm = sorted(((c.method_idx(m.ref), m) for m in cl.virtual), key=lambda x: x[0])
        b = bytearray()
        b += uleb(0) + uleb(len(flds)) + uleb(len(dm)) + uleb(len(vm))
        prev = 0
        for fi, fl in flds:
            b += uleb(fi - prev) + uleb(fl); prev = fi
        for lst in (dm, vm):
            prev = 0
            for mi, m in lst:
                b += uleb(mi - prev) + uleb(m.flags) + uleb(code_off[m.ref.key()]); prev = mi
        data += b
    map_entries.append((0x2000, len(classes), cd_start))

    # string data
    sd_off = []
    sd_start = here()
    for s in S:
        sd_off.append(here())
        data += uleb(len(s.encode("utf-16-le")) // 2) + mutf8(s) + b"\0"
    map_entries.append((0x2002, len(S), sd_start))

    # map list
    align(4)
    map_off = here()
    map_entries.append((0x1000, 1, map_off))

    # assemble id sections
    ids = bytearray()
    for o in sd_off: ids += struct.pack("<I", o)
    for t in TY: ids += struct.pack("<I", sidx[t])
    for p in PR:
        ids += struct.pack("<III", sidx[shorty(p)], tidx[p[0]], tl_off.get(p[1], 0) if p[1] else 0)
    for f in FL: ids += struct.pack("<HHI", tidx[f[0]], tidx[f[2]], sidx[f[1]])
    for m in ML: ids += struct.pack("<HHI", tidx[m[0]], pidx[(m[2], m[3])], sidx[m[1]])
    for cl in classes:
        ifo = tl_off[cl.interfaces] if cl.interfaces else 0
        ids += struct.pack("<IIIIIIII", tidx[cl.desc], cl.flags, tidx[cl.sup], ifo,
                           0xffffffff, ad_off.get(cl.desc, 0), cd_off[cl.desc], 0)

    # map list content
    fixed = [
        (0x0000, 1, 0),
        (0x0001, len(S), string_ids_off),
        (0x0002, len(TY), type_ids_off),
        (0x0003, len(PR), proto_ids_off),
        (0x0004, len(FL), field_ids_off),
        (0x0005, len(ML), method_ids_off),
        (0x0006, len(classes), class_defs_off),
    ]
    allm = sorted([e for e in fixed + map_entries if e[1] > 0], key=lambda e: e[2])
    mp = struct.pack("<I", len(allm)) + b"".join(struct.pack("<HHII", t, 0, n, o) for t, n, o in allm)
    data += mp

    file_size = data_off + len(data)
    hdr = bytearray(b"dex\n035\0")
    hdr += b"\0" * 4 + b"\0" * 20
    hdr += struct.pack("<IIII", file_size, hdr_size, 0x12345678, 0)
    hdr += struct.pack("<I", 0)  # link_off
    hdr += struct.pack("<I", map_off)
    hdr += struct.pack("<II", len(S), string_ids_off)
    hdr += struct.pack("<II", len(TY), type_ids_off)
    hdr += struct.pack("<II", len(PR), proto_ids_off)
    hdr += struct.pack("<II", len(FL), field_ids_off)
    hdr += struct.pack("<II", len(ML), method_ids_off)
    hdr += struct.pack("<II", len(classes), class_defs_off)
    hdr += struct.pack("<II", len(data), data_off)
    assert len(hdr) == hdr_size, len(hdr)
    blob = bytearray(hdr) + ids
    assert len(blob) == data_off, (len(blob), data_off)
    blob += data
    sha = hashlib.sha1(bytes(blob[32:])).digest()
    blob[12:32] = sha
    blob[8:12] = struct.pack("<I", zlib.adler32(bytes(blob[12:])) & 0xffffffff)
    return bytes(blob)

if __name__ == "__main__":
    out = sys.argv[1]
    open(out, "wb").write(build_dex(build_classes()))
    print("wrote", out)
