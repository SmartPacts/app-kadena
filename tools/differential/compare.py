"""Compare C and Rust differential results and classify every difference.

    python compare.py results/*-c.json results/*-rust.json --report report.md

A case is OK when every response (and every marker) is identical. A difference
is EXPLAINED only when it maps to an intended divergence of the port and the
Rust side shows the designed behaviour:

  VERSION  version bytes 1.3.0 -> 2.0.0 (INS 0x20 bytes 1-6, INS 0x00 bytes 0-2)
  V1       legacy 0x10: the Rust side answers 0x6700 where an item runs past rx
  V2       structured transfer field outside the allowlist: Rust 0x6984
           ("Unexpected characters" on 0x24, bare on 0x10)
  V3       only the "Unscoped Signer" marker differs, present on the Rust side
  V4       the JSON has a duplicate key: Rust "Unexpected duplicated field" 0x6984
           (bare 0x6984 on legacy 0x03)
  V5, V8   the first differing response is the Rust side's 0x6987 (a chunk of
           another INS, or of the other family, while a stream is open)
  V7       the Rust signature verifies under the stream's key, the C one under
           the key of the 0x02 sent in the middle of the stream
  V9       the JSON's signer entries do not name the device key exactly once
           (recomputed here with the device's own lookup rules): Rust "Device key
           is not a signer" / "... signs more than once" 0x6984 (bare on 0x03)
  V10/V11  the C app showed a WARNING or CAUTION page (an unscoped signer, an
           undisplayable value, an unrecognised meta) and signed with blind
           signing OFF: Rust "Blind signing mode required" 0x6984
  V12      the JSON holds a NUL or bytes after its value: Rust "Unexpected
           characters" / "Unexpected unparsed bytes" 0x6984 (bare on 0x03)
  V13      only screen text differs: the Rust side showed the \\xNN escape
  V14      the device's signer entry holds coin.ROTATE: Rust "Blind signing mode
           required" 0x6984 with the setting OFF (C signed)
  V15, V16, V19  only screen text differs, by what the Rust side adds: the
           maximum fee and paying account (V15), a WARNING for a receiver that is
           not a principal (V16), the expert validity window (V19); a WARNING
           marker difference is explained only when the transaction holds one of
           those (or a capability V20 flags, or coin.ROTATE: V14).
  V20      in host-built JSON (0x22, 0x03), a capability of the device's entry
           other than coin.GAS and a full coin.TRANSFER / coin.TRANSFER_XCHAIN
           (coin.ROTATE: V14): Rust "Blind signing mode required" 0x6984 with
           the setting OFF; with it ON only screens differ (a WARNING).
  V21      a transfer amount in exponent notation: Rust "Unexpected characters"
  V23      a structured token transfer (0x24, 0x10 with namespace and module):
           Rust "Blind signing mode required" with the setting OFF
  V24      a coin transfer amount in neither accepted form (bare number, or
           {"decimal": "<number>"} with a quoted single key): "Unexpected
           characters"; a decimal-object amount is shown as the number
  V25      a coin transfer amount with more than 12 fractional digits:
           "Unexpected characters" (host JSON and coin structured transfers)
  V26      a structured transfer amount without a fractional part:
           "Unexpected characters" (bare 0x6984 on 0x10)
  V15      also: gasLimit, ttl or creationTime not plain digits: Rust
           "Unexpected characters"
  V22      a "verifiers" field: Rust "Unexpected value"
  V3       also: a scoped signature the C app titled "Unscoped Signer" is titled
           "Key not in transfer"
  V18      an object key holds a backslash (anywhere), or a capability name of
           the device's entry does: Rust "Unexpected characters" 0x6984 (bare on
           0x03). A literal duplicate key in a nested object is V4.
Any case (tagged or not) may be explained by V9, V11 or V12, since those follow
from the input and the C screens alone.
Anything else is UNEXPLAINED and fails the run.
"""

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict

import corpus

DUP = "Unexpected duplicated field".encode().hex() + "6984"
BADCHARS = "Unexpected characters".encode().hex() + "6984"
UNPARSED = "Unexpected unparsed bytes".encode().hex() + "6984"
NOT_SIGNER = "Device key is not a signer".encode().hex() + "6984"
SIGNS_TWICE = "Device key signs more than once".encode().hex() + "6984"
BLIND = "Blind signing mode required".encode().hex() + "6984"
# v9_refusal's answer for an escaped capability name in the device's entry (V18).
CAPNAME = "V18:" + BADCHARS
# The test seed's keys by path (the corpus signs with these three paths).
KEYS = {bytes(corpus.le(corpus.STD)): corpus.EXPECTED_PK, bytes(corpus.le(corpus.ALT)): corpus.ALT_PK}


def jsmn(js: bytes, cap=768):
    """Python port of the device tokenizer (non-strict jsmn): list of
    [kind, start, end] or None on error. kind: 1 object, 2 array, 4 string, 8 primitive."""
    js = js.split(b"\0")[0]
    toks, sup, pos, n = [], -1, 0, len(js)

    def open_(t):
        return t[1] != -1 and t[2] == -1

    while pos < n:
        c = js[pos]
        if c in b"{[":
            toks.append([1 if c == 0x7B else 2, pos, -1])
            sup = len(toks) - 1
        elif c in b"}]":
            kind = 1 if c == 0x7D else 2
            i = len(toks) - 1
            while i >= 0 and not open_(toks[i]):
                i -= 1
            if i < 0 or toks[i][0] != kind:
                return None
            toks[i][2] = pos + 1
            sup = -1
            while i >= 0 and not open_(toks[i]):
                i -= 1
            if i >= 0:
                sup = i
        elif c == 0x22:
            start, pos = pos, pos + 1
            while pos < n and js[pos] != 0x22:
                if js[pos] == 0x5C and pos + 1 < n:
                    pos += 1
                    if js[pos] == 0x75:
                        pos += 4
                    elif js[pos] not in b'"/\\bfrnt':
                        return None
                pos += 1
            if pos >= n:
                return None
            toks.append([4, start + 1, pos])
        elif c in b"\t\r\n ":
            pass
        elif c == 0x3A:
            sup = len(toks) - 1
        elif c == 0x2C:
            if sup < 0 or toks[sup][0] not in (1, 2):
                for i in range(len(toks) - 1, -1, -1):
                    if toks[i][0] in (1, 2) and open_(toks[i]):
                        sup = i
                        break
        else:
            start = pos
            while pos < n and js[pos] not in b":\t\r\n ,]}":
                if js[pos] < 32 or js[pos] >= 127:
                    return None
                pos += 1
            toks.append([8, start, pos])
            pos -= 1
        pos += 1
    if any(open_(t) for t in toks) or len(toks) > cap:
        return None
    return toks


def has_duplicate_keys(raw: bytes) -> bool:
    """True if some object repeats a key, walking keys the way the device does
    (object_get_nth_key) and decoding escapes."""
    toks = jsmn(raw)
    if not toks:
        return False
    for oi, ot in enumerate(toks):
        if ot[0] != 1:
            continue
        keys, ti, prev = [], oi + 1, ot[1]
        while ti + 1 < len(toks):
            k, v = toks[ti], toks[ti + 1]
            ti += 1
            if k[1] > ot[2]:
                break
            if k[1] <= prev:
                continue
            prev = v[2]
            text = raw[k[1]:k[2]]
            if k[0] == 4:
                try:
                    text = json.loads(b'"' + text + b'"')
                except ValueError:
                    pass
            keys.append(text)
        if len(keys) != len(set(map(repr, keys))):
            return True
    return False


class Json:
    """The device's JSON lookups (kadena-core json.rs) over jsmn() tokens."""

    def __init__(self, raw, toks):
        self.raw, self.t = raw, toks

    def tok(self, i):
        return self.t[i] if 0 <= i < len(self.t) else [0, 0, 0]

    def span(self, i):
        _, a, b = self.tok(i)
        return self.raw[a:b]

    def arr_count(self, a):
        at, ti, prev, n = self.tok(a), a, self.tok(a)[1], 0
        while True:
            ti += 1
            if ti >= len(self.t):
                return n
            cur = self.tok(ti)
            if cur[1] > at[2]:
                return n
            if cur[1] <= prev:
                continue
            prev, n = cur[2], n + 1

    def arr_nth(self, a, k):
        at, ti, prev, n = self.tok(a), a, self.tok(a)[1], 0
        while ti < len(self.t):
            ti += 1
            if ti >= len(self.t):
                break
            cur = self.tok(ti)
            if cur[1] > at[2]:
                break
            if cur[1] <= prev:
                continue
            prev = cur[2]
            if n == k:
                return ti
            n += 1
        return None

    def _pairs(self, o):
        """(key index) of each key of object `o`, with the device's skipping rule."""
        ot, ti, prev = self.tok(o), o + 1, self.tok(o)[1]
        while ti < len(self.t):
            key = self.tok(ti)
            ti += 1
            if ti >= len(self.t):
                return
            value = self.tok(ti)
            if key[1] > ot[2]:
                return
            if key[1] <= prev:
                continue
            prev = value[2]
            yield ti - 1

    def obj_get(self, o, key):
        """object_get_value: the first key with these raw bytes; value index."""
        if o >= len(self.t):
            return None
        ot, ti, prev = self.tok(o), o + 1, self.tok(o)[1]
        while ti < len(self.t):
            k = self.tok(ti)
            ti += 1
            if ti >= len(self.t):
                break
            v = self.tok(ti)
            if k[1] > ot[2]:
                break
            if k[1] <= prev:
                continue
            prev = v[2]
            if self.raw[k[1]:k[2]] == key:
                return ti
        return None


def v12_refusal(raw):
    """The Rust answer if V12 refuses `raw`, else None."""
    if b"\0" in raw:
        return BADCHARS
    toks = jsmn(raw)
    if not toks:
        return None
    end = toks[0][2] + (1 if toks[0][0] == 4 else 0)
    if raw[end:].strip(b" \t\r\n"):
        return UNPARSED
    return None


def v9_refusal(raw, pk, cap=768):
    """The Rust answer if V9 refuses `raw` for device key `pk`, else None
    (kadena-core items::find_device_signer)."""
    toks = jsmn(raw, cap)
    if not toks or v12_refusal(raw) or key_refusal(raw, cap):
        return None
    j, pk = Json(raw, toks), pk.encode()
    signers = j.obj_get(0, b"signers")
    if signers is None or j.tok(signers)[0] != 2:
        return NOT_SIGNER
    found, matches = None, 0
    for i in range(j.arr_count(signers)):
        e = j.arr_nth(signers, i)
        if e is None or j.tok(e)[0] != 1:
            continue
        if any(b"\\" in j.span(k) for k in j._pairs(e)):
            return BADCHARS
        names = False
        for field in (b"pubKey", b"addr"):
            v = j.obj_get(e, field)
            if v is not None:
                if b"\\" in j.span(v):
                    return BADCHARS
                names |= j.span(v).lower() == pk.lower()
        if names:
            matches, found = matches + 1, e
    if matches == 0:
        return NOT_SIGNER
    if matches > 1:
        return SIGNS_TWICE
    v = j.obj_get(found, b"pubKey")
    if v is None or j.tok(v)[0] != 4 or j.span(v) != pk:
        return NOT_SIGNER
    # V18: an escaped capability name in the device's entry.
    cl = j.obj_get(found, b"clist")
    if cl is not None and j.tok(cl)[0] == 2:
        for k in range(j.arr_count(cl)):
            nt = j.obj_get(j.arr_nth(cl, k), b"name")
            if nt is not None and b"\\" in j.span(nt):
                return CAPNAME
    return None


def key_refusal(raw, cap=768):
    """kadena-core json::check_key_integrity: in token order, per object, a key
    with a backslash (V18, "Unexpected characters") or a key equal, byte for
    byte, to an earlier key of its object (V4, "Unexpected duplicated field")."""
    toks = jsmn(raw, cap)
    if not toks:
        return None
    j = Json(raw, toks)
    for o, t in enumerate(toks):
        if t[0] != 1:
            continue
        seen = []
        for k in j._pairs(o):
            key = j.span(k)
            if b"\\" in key:
                return BADCHARS
            if key in seen:
                return DUP
            seen.append(key)
    return None


def json_input(case):
    """(raw JSON, device key, legacy) of a 0x22/0x03 case, else None."""
    ins = {bytes.fromhex(s["apdu"])[1] for s in case["steps"]}
    if ins == {0x22}:
        first = bytes.fromhex(case["steps"][0]["apdu"])[5:25]
        return modern_payload(case["steps"], 0x22), KEYS.get(first), False
    if ins == {0x03}:
        lp = legacy_payload(case["steps"], 0x03)
        n = int.from_bytes(lp[:4], "little")
        path = lp[4 + n:]
        pk = {1 + 4 * 5: corpus.EXPECTED_PK, 1 + 4 * 2: corpus.PK2}.get(len(path))
        if pk == corpus.EXPECTED_PK and path != corpus.legacy_path(corpus.STD):
            pk = None
        return lp[4:4 + n], pk, True
    return None


def allowlist_violation(body: bytes) -> bool:
    """Re-implements the V2 allowlist on a 0x24 body (tx_type + 12 fields)."""
    if not body:
        return False
    off, fields = 1, []
    for _ in range(12):
        if off >= len(body):
            return False
        n = body[off]
        off += 1
        if off + n > len(body):
            return False
        fields.append(body[off:off + n])
        off += n
    if off != len(body) or body[0] > 2:
        return False
    caps = [64, 2, 20, 32, 63, 32, 20, 10, 12, 2, 32, 20]
    if len(fields[0]) != 64 or any(len(f) > c for f, c in zip(fields[1:], caps[1:])):
        return False
    ident = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789%#+-_&$@<>=?*!|/")
    digits = set(b"0123456789")
    dec = re.compile(rb"[0-9]+(\.[0-9]+)?")
    num = re.compile(rb"[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?")
    ok = [
        set(fields[0]) <= set(b"0123456789abcdef"),
        set(fields[1]) <= digits and (body[0] != 2 or fields[1] != b""),
        set(fields[2]) <= set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."),
        dec.fullmatch(fields[3]) is not None,
        set(fields[4]) <= ident,
        set(fields[5]) <= ident,
        num.fullmatch(fields[6]) is not None,
        dec.fullmatch(fields[7]) is not None,
        dec.fullmatch(fields[8]) is not None,
        set(fields[9]) <= digits and fields[9] != b"",
        all(0x20 <= b < 0x7F and b not in b'"\\' for b in fields[10]),
        dec.fullmatch(fields[11]) is not None,
    ]
    return not all(ok)


def modern_payload(steps, ins):
    data = b""
    for s in steps:
        a = bytes.fromhex(s["apdu"])
        if a[1] == ins and a[2] in (1, 2):
            data += a[5:]
    return data


def legacy_payload(steps, ins):
    data = b""
    for s in steps:
        a = bytes.fromhex(s["apdu"])
        if a[1] == ins:
            data += a[5:]
    return data


def explain(case, c, r, device=""):
    """Returns the V-tag that explains the difference, or None."""
    why = explain_tagged(case, c, r)
    if why is not None:
        return why
    why = explain_json(case, c, r, device)
    if why is not None:
        return why
    return explain_transfer(case, c, r)


def transfer_fields(body):
    """(tx_type, 12 fields) of a 0x24 body, or None if it does not parse."""
    if not body:
        return None
    off, fields = 1, []
    for _ in range(12):
        if off >= len(body):
            return None
        n = body[off]
        off += 1
        if off + n > len(body):
            return None
        fields.append(body[off:off + n])
        off += n
    return (body[0], fields) if off == len(body) else None


def explain_transfer(case, c, r):
    """V23 (token transfer, blind signing OFF) and V15 (integer gas fields) on
    structured transfers the allowlist accepts."""
    ins = {bytes.fromhex(s["apdu"])[1] for s in case["steps"]}
    if not ins & {0x24, 0x10} or ins - {0x24, 0x10}:
        return None
    cs = [s["response"] for s in c["steps"]]
    rs = [s["response"] for s in r["steps"]]
    if cs[:-1] != rs[:-1] or "crash" in r:
        return None
    body = modern_payload(case["steps"], 0x24) if 0x24 in ins else legacy_payload(case["steps"], 0x10)
    if 0x10 in ins and body:
        body = body[1 + 4 * body[0]:]
    tf = transfer_fields(body)
    if tf is None or allowlist_violation(body):
        return None
    tx_type, f = tf
    legacy = 0x10 in ins
    refused = rs[-1] == ("6984" if legacy else BADCHARS)
    # V26: the amount needs a fractional part (Pact refuses an integer).
    if b"." not in f[3]:
        return "V26" if refused else None
    # V24, V25 on a coin transfer's amount (reviewed as coin.TRANSFER).
    if not (f[4] and f[5]) and not AMOUNT.fullmatch(f[3]):
        return ("V25" if re.fullmatch(rb"(0|[1-9][0-9]*)\.[0-9]{13,}", f[3]) else "V24") if refused else None
    if any(not re.fullmatch(rb"[0-9]+", f[i]) for i in (7, 8, 11)):
        return "V15" if rs[-1] == ("6984" if legacy else BADCHARS) else None
    if f[4] and f[5] and case["session"] == "default" and rs[-1] == BLIND:
        return "V23"
    return None


def explain_json(case, c, r, device):
    """V9 / V11 / V12 on any JSON case, recomputed from the input and C's screens."""
    inp = json_input(case)
    if not inp:
        return None
    raw, pk, legacy = inp
    cs = [s["response"] for s in c["steps"]]
    rs = [s["response"] for s in r["steps"]]
    if cs[:-1] != rs[:-1] or "crash" in r:
        return None
    last = rs[-1]
    v12 = v12_refusal(raw)
    if v12:
        return "V12" if last == (("6984") if legacy else v12) else None
    keys = key_refusal(raw, 110 if device == "nanox" else 768)
    if keys:
        tag = "V18" if keys == BADCHARS else "V4"
        return tag if last == ("6984" if legacy else keys) else None
    toks = jsmn(raw, 110 if device == "nanox" else 768)
    if toks and Json(raw, toks).obj_get(0, b"verifiers") is not None:
        return "V22" if last == ("6984" if legacy else UNEXPECTED_VALUE) else None
    if pk is None:
        return None
    v9 = v9_refusal(raw, pk, 110 if device == "nanox" else 768)
    if v9 == CAPNAME:
        return "V18" if last == ("6984" if legacy else BADCHARS) else None
    if v9:
        return "V9" if last == ("6984" if legacy else v9) else None
    r3 = round3_refusal(raw, pk)
    if r3:
        tag, code = r3
        return tag if last == ("6984" if legacy else code) else None
    if case["session"] != "default" or last != BLIND or any(r["markers"].values()):
        return None
    flags = device_caps(raw, pk)
    if "rotate" in flags:
        return "V14"
    if c["markers"].get("WARNING") or c["markers"].get("CAUTION"):
        return "V11"
    if "unverified" in flags:
        return "V20"
    if device_clist_empty(raw, pk):
        return "V10"
    return None


UNEXPECTED_VALUE = "Unexpected value".encode().hex() + "6984"
META_KEYS = [b"creationTime", b"ttl", b"gasLimit", b"chainId", b"gasPrice", b"sender"]


AMOUNT = re.compile(rb"(0|[1-9][0-9]*)(\.[0-9]{1,12})?")


def amount_form_ok(j, a):
    """V24: a bare number, or {"decimal": "<number>"} with that single, quoted
    key; V25: at most 12 fractional digits."""
    if j.tok(a)[0] == 8:
        return AMOUNT.fullmatch(j.span(a)) is not None
    pairs = list(j._pairs(a)) if j.tok(a)[0] == 1 else []
    if len(pairs) == 1 and j.tok(pairs[0])[0] == 4:
        v = j.obj_get(a, b"decimal")
        return v is not None and j.tok(v)[0] == 4 and AMOUNT.fullmatch(j.span(v)) is not None
    return False


def amount_tag(j, a):
    """V25 when only the 12-place bound refuses the amount, else V24."""
    span = j.span(a) if j.tok(a)[0] == 8 else None
    if span is None and j.tok(a)[0] == 1:
        v = j.obj_get(a, b"decimal")
        span = j.span(v) if v is not None and j.tok(v)[0] == 4 else None
    if span is not None and re.fullmatch(rb"(0|[1-9][0-9]*)\.[0-9]{13,}", span):
        return "V25"
    return "V24"


def round3_refusal(raw, pk):
    """(tag, Rust answer) for the round-3 refusals after the signer lookup, in
    the app's order: V21 (exponent transfer amount in the device's entry) or V24
    (an amount in neither accepted form, see amount_form_ok), then
    V15 (non-integer gas fields). V22 (verifiers) comes before the lookup."""
    toks = jsmn(raw)
    if not toks:
        return None
    j = Json(raw, toks)
    signers = j.obj_get(0, b"signers")
    for i in range(j.arr_count(signers) if signers is not None else 0):
        e = j.arr_nth(signers, i)
        v = j.obj_get(e, b"pubKey") if e is not None else None
        if v is None or j.span(v) != pk.encode():
            continue
        cl = j.obj_get(e, b"clist")
        if cl is None or j.tok(cl)[0] != 2:
            break
        for k in range(j.arr_count(cl)):
            cap = j.arr_nth(cl, k)
            nt = j.obj_get(cap, b"name")
            args = j.obj_get(cap, b"args")
            if nt is None or args is None:
                continue
            want = {b"coin.TRANSFER": 3, b"coin.TRANSFER_XCHAIN": 4}.get(j.span(nt))
            if want and j.arr_count(args) == want:
                a = j.arr_nth(args, 2)
                if j.tok(a)[0] == 8 and re.search(rb"[eE]", j.span(a)):
                    return ("V21", BADCHARS)
                if not amount_form_ok(j, a):
                    return (amount_tag(j, a), BADCHARS)
        break
    meta = j.obj_get(0, b"meta")
    if meta is not None and j.tok(meta)[0] == 1:
        keys = [j.span(k) for k in j._pairs(meta)]
        if len(keys) <= 6 and keys == META_KEYS[:len(keys)]:
            for f in (b"creationTime", b"ttl", b"gasLimit"):
                v = j.obj_get(meta, f)
                if v is not None and (j.tok(v)[0] != 8 or not re.fullmatch(rb"[0-9]+", j.span(v))):
                    return ("V15", BADCHARS)
    return None


def device_caps(raw, pk):
    """What the device's signer entry holds that round 2 flags: "rotate"
    (coin.ROTATE), "vanity" (a transfer to a non-principal), "unverified"
    (V20: anything but coin.GAS and full coin transfers)."""
    toks = jsmn(raw)
    if not toks or pk is None:
        return set()
    j = Json(raw, toks)
    signers = j.obj_get(0, b"signers")
    if signers is None:
        return set()
    out = set()
    for i in range(j.arr_count(signers)):
        e = j.arr_nth(signers, i)
        v = j.obj_get(e, b"pubKey") if e is not None else None
        if v is None or j.span(v) != pk.encode():
            continue
        cl = j.obj_get(e, b"clist")
        if cl is None or j.tok(cl)[0] != 2:
            continue
        for k in range(j.arr_count(cl)):
            cap = j.arr_nth(cl, k)
            nt = j.obj_get(cap, b"name")
            name = j.span(nt) if nt is not None else b""
            args = j.obj_get(cap, b"args")
            n = j.arr_count(args) if args is not None else -1
            if name == b"coin.ROTATE":
                out.add("rotate")
            elif not (name == b"coin.GAS" or (name == b"coin.TRANSFER" and n == 3)
                      or (name == b"coin.TRANSFER_XCHAIN" and n == 4)):
                out.add("unverified")
            elif name in (b"coin.TRANSFER", b"coin.TRANSFER_XCHAIN"):
                if not is_principal(j.span(j.arr_nth(args, 1))):
                    out.add("vanity")
    return out


def is_principal(s):
    """kadena-core principal::is_principal (pact-5 principalParser, ASCII idents)."""
    ident = rb"[A-Za-z%#+\-_&$@<>=^?*!|/~][A-Za-z0-9%#+\-_&$@<>=^?*!|/~]*"
    name = ident + rb"(\." + ident + rb"(\." + ident + rb")?)?"
    h = rb"[A-Za-z0-9\-_]{43}"
    if re.fullmatch(rb"k:[0-9a-fA-F]{64}", s) or re.fullmatch(rb"r:.+", s, re.S) or re.fullmatch(rb"c:" + h, s):
        return True
    for pat in (rb"w:" + h + rb":" + name, rb"u:" + name + rb":" + h,
                rb"m:" + ident + rb"(\." + ident + rb")?:" + name, rb"p:" + h + rb":" + name):
        m = re.fullmatch(pat, s)
        if m and not re.search(rb"(^|[:.])(true|false)(?=$|[:.])", s[2:]):
            return True
    return False


def device_clist_empty(raw, pk):
    """The device's signer entry has `"clist": []` (C: scoped to nothing, no warning)."""
    toks = jsmn(raw)
    j = Json(raw, toks)
    signers = j.obj_get(0, b"signers")
    for i in range(j.arr_count(signers)):
        e = j.arr_nth(signers, i)
        v = j.obj_get(e, b"pubKey") if e is not None else None
        if v is not None and j.span(v) == pk.encode():
            cl = j.obj_get(e, b"clist")
            return cl is not None and j.tok(cl)[0] == 2 and j.arr_count(cl) == 0
    return False


def explain_tagged(case, c, r):
    """Returns the V-tag that explains the difference, or None."""
    why = explain_tagged_base(case, c, r)
    if why is not None:
        return why
    # A WARNING page only the Rust side showed, responses equal: V16/V20/V14 when
    # the device's entry holds what they flag.
    cs = [s["response"] for s in c["steps"]]
    rs = [s["response"] for s in r["steps"]]
    diff = [k for k in c["markers"] if c["markers"][k] != r["markers"][k]]
    if cs == rs and diff == ["WARNING"] and r["markers"]["WARNING"]:
        inp = json_input(case)
        flags = device_caps(inp[0], inp[1]) if inp else set()
        for flag, tag in (("vanity", "V16"), ("unverified", "V20"), ("rotate", "V14")):
            if flag in flags:
                return tag
    return None


def explain_tagged_base(case, c, r):
    """Returns the V-tag that explains the difference, or None."""
    tag = case["tag"]
    cs = [s["response"] for s in c["steps"]]
    rs = [s["response"] for s in r["steps"]]
    ins = {bytes.fromhex(s["apdu"])[1] for s in case["steps"]}
    if tag == "VERSION":
        ok = True
        for s, a, b in zip(case["steps"], cs, rs):
            ap = bytes.fromhex(s["apdu"])
            if a == b:
                continue
            if ap[1] == 0x20:
                ok &= a[:2] + a[14:] == b[:2] + b[14:] and b[2:14] == "000200000000"
            elif ap[1] == 0x00:
                ok &= b == "0200009000" and a[-4:] == b[-4:]
            else:
                ok = False
        return "VERSION" if ok else None
    # A version APDU inside a case (e.g. the R3 primer) differs by the version bytes only.
    cs = list(cs)
    for k, st in enumerate(case["steps"]):
        ap = bytes.fromhex(st["apdu"])
        if ap[1] == 0x20 and ap[0] == 0 and k < len(rs) and cs[k][:2] + cs[k][14:] == rs[k][:2] + rs[k][14:]:
            cs[k] = rs[k]
    if cs == rs:
        if c["markers"] != r["markers"]:
            diff = [k for k in c["markers"] if c["markers"][k] != r["markers"][k]]
            if (set(diff) == {"Unscop", "Key not in"} and c["markers"]["Unscop"] and r["markers"]["Key not in"]
                    and not r["markers"]["Unscop"] and not c["markers"]["Key not in"]):
                # F6: the same scoped signature, titled "Key not in transfer".
                return "V3"
            if all(r["markers"][k] for k in diff):
                # Only screens differ, and only by what the Rust side adds.
                # (A scoped signature's title is "Key not in transfer" since F6.)
                if tag == "V3" and diff in (["Unscop"], ["Key not in"]):
                    return "V3"
                if tag in ("V14", "V15", "V16", "V19", "V20", "V23") and set(diff) <= set(case["markers"]) - {"CAUTION"}:
                    return tag
                if tag in ("V9", "V10") and set(diff) <= {"Unscop", "WARNING", "Signers"}:
                    return tag
                if tag == "V13" and all(k.startswith("k:") for k in diff if k != "WARNING"):
                    # The accounts are not principals, so V16 adds a WARNING too.
                    inp = json_input(case)
                    if "WARNING" not in diff or (inp and "vanity" in device_caps(inp[0], inp[1])):
                        return "V13"
            return None
        return "SAME"
    if tag == "V1" or (tag == "FUZZ" and ins == {0x10}):
        if "6700" in [x[-4:] for x in rs] and any(a != b for a, b in zip(cs, rs)):
            first = next(i for i, (a, b) in enumerate(zip(cs, rs)) if a != b)
            if rs[first][-4:] == "6700":
                return "V1"
    if tag in ("V2", "FUZZ") and ins & {0x24, 0x10}:
        body = modern_payload(case["steps"], 0x24) if 0x24 in ins else legacy_payload(case["steps"], 0x10)
        if 0x10 in ins and body:
            q = body[0]
            body = body[1 + 4 * q:]
        if allowlist_violation(body) and (rs[-1] == BADCHARS or rs[-1] == "6984"):
            return "V2"
    if tag in ("V4", "FUZZ") and ins & {0x22, 0x03}:
        if 0x22 in ins:
            raw = modern_payload(case["steps"], 0x22)
        else:
            lp = legacy_payload(case["steps"], 0x03)
            raw = lp[4:4 + int.from_bytes(lp[:4], "little")]
        if has_duplicate_keys(raw) and (rs[-1] == DUP or (0x03 in ins and rs[-1] == "6984")):
            return "V4"
    if tag in ("V5", "V8"):
        first = next(i for i, (a, b) in enumerate(zip(cs, rs)) if a != b)
        if rs[first][-4:] == "6987":
            return tag
    if tag == "V7":
        return "V7" if v7_holds(case, cs, rs) else None
    if tag == "V13" and "crash" in c and not any(x == "CRASH" for x in rs):
        # The C app stops the touch emulator on such bytes (see below).
        return "V13" if all(r["markers"][m] for m in case["markers"] if m.startswith("k:")) else None
    return None


def v7_holds(case, cs, rs):
    """The Rust signature verifies under the INIT path's key (step 1), the C one
    under the 0x02 path's key (step 2)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    msg = hashlib.blake2b(modern_payload(case["steps"], 0x22), digest_size=32).digest()
    pk_a = bytes.fromhex(rs[0][:-4])
    pk_b = bytes.fromhex(rs[1][:-4])[1:]

    def ok(pk, sig_hex):
        try:
            Ed25519PublicKey.from_public_bytes(pk).verify(bytes.fromhex(sig_hex[:-4]), msg)
            return True
        except Exception:  # noqa: BLE001
            return False

    return ok(pk_a, rs[-1]) and not ok(pk_b, rs[-1]) and ok(pk_b, cs[-1]) and not ok(pk_a, cs[-1])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--report", required=True)
    args = ap.parse_args()
    runs = defaultdict(dict)
    for f in args.files:
        d = json.load(open(f))
        runs[d["device"]][d["label"]] = d
    cases = {c["name"]: c for c in corpus.cases()}
    lines, total, bad = [], Counter(), []
    lines.append("# C v1.3.0 vs Rust 2.0.0 — differential report\n")
    lines.append("| device | cases | APDUs | identical | explained | unexplained |")
    lines.append("|---|---|---|---|---|---|")
    detail = []
    crashes = []
    for dev in sorted(runs):
        c_run, r_run = runs[dev].get("c"), runs[dev].get("rust")
        if not c_run or not r_run:
            print(f"{dev}: missing a side", file=sys.stderr)
            sys.exit(2)
        rmap = {x["name"]: x for x in r_run["cases"]}
        count = Counter()
        napdu = 0
        for cc in c_run["cases"]:
            rr = rmap.get(cc["name"])
            case = cases[cc["name"]]
            napdu += len(cc["steps"])
            if rr is None or len(rr["steps"]) != len(cc["steps"]):
                count["unexplained"] += 1
                bad.append((dev, cc["name"], "missing on the Rust side"))
                continue
            if "crash" in rr:
                count["unexplained"] += 1
                bad.append((dev, cc["name"], "Rust side crashed: " + rr["crash"]))
                continue
            why = explain(case, cc, rr, dev)
            if why == "SAME":
                count["identical"] += 1
                continue
            if why is None:
                count["unexplained"] += 1
                bad.append((dev, cc["name"], json.dumps({"c": [s["response"] for s in cc["steps"]],
                                                         "rust": [s["response"] for s in rr["steps"]],
                                                         "markers": [cc["markers"], rr["markers"]]})))
                continue
            count["explained"] += 1
            total[why] += 1
            if "crash" in cc:
                crashes.append((dev, cc["name"], why))
            detail.append(f"| {dev} | {cc['name']} | {why} | "
                          f"`{' '.join(s['response'][-4:] for s in cc['steps'])}` | "
                          f"`{' '.join(s['response'][-4:] for s in rr['steps'])}` |")
        n = len(c_run["cases"])
        lines.append(f"| {dev} | {n} | {napdu} | {count['identical']} | {count['explained']} | {count['unexplained']} |")
    lines.append("\nExplained differences by cause: " + ", ".join(f"{k}: {v}" for k, v in sorted(total.items())))
    lines.append("\n## Explained differences (status words: C / Rust, one per APDU)\n")
    lines.append("| device | case | cause | C | Rust |")
    lines.append("|---|---|---|---|---|")
    lines += detail
    lines.append("\n## Emulator stopped on the C side\n")
    lines.append("Speculos exits (UnicodeDecodeError) when the C app draws bytes that are not UTF-8 on a touch "
                 "screen; the C response is then unavailable. The Rust app refuses these inputs.\n")
    lines += [f"- {d} / {n} (Rust: {w} refusal)" for d, n, w in crashes] or ["None."]
    lines.append("\n## Unexplained differences\n")
    lines += [f"- {d} / {n}: {w}" for d, n, w in bad] or ["None."]
    open(args.report, "w").write("\n".join(lines) + "\n")
    print("\n".join(lines[:12]))
    print(f"unexplained: {len(bad)}")
    for b in bad[:30]:
        print("  ", b)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
