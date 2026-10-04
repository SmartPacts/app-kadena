"""APDU corpus for the C-vs-Rust differential run.

Each case is a list of steps (one APDU each, with the decision to take if the
device shows a review) plus an optional tag naming the intended divergence the
case exercises ("V1".."V13", or "VERSION" for the version bytes). Untagged cases
must produce byte-identical responses from the C v1.3.0 app and this app, except
where compare.py can show from the input itself that V9, V11 or V12 applies.

V9: the Rust app reviews and signs only for the signer entry carrying the device
key. The C fixtures below name other keys (the C app read signers[0] whatever it
was), so every JSON fixture is re-keyed to the test seed's key for its path; the
originals are kept as V9 cases. JSON cases record whether a WARNING or CAUTION
page was shown, which is how compare.py recognises V11 (blind signing).

Sources: the C app's Zemu suite (every protocol-level case), the C app's C++ UI
vectors (kadena-core/tests/vectors/testcases.json), the emulator reproduction of
the C findings (R3: F-A, F-B, #3, #4, #5), hand-written negative cases for every
error path, and deterministic mutations of valid inputs ("fuzz" cases).
"""

import json
import random
from pathlib import Path

H = 0x80000000
BS = chr(92)  # a backslash
STD = [H | 44, H | 626, H | 0, 0, 0]
ALT = [H | 44, H | 626, H | 5, 0, 0]
EXPECTED_PK = "de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad"
# The test seed's keys at m/44'/626'/5'/0/0 and m/44'/626' (as the 0x21 and 0x02
# cases of an earlier run answered them, identical on both apps).
ALT_PK = "ba851670b93b119aa18f064e82d165c74cf8bf41744e14b1a794dc85bdf7d758"
PK2 = "19d87ede176e5b6efbb4eb1c91cc1fa9417e38f5205e8fe4e25a7aa0e41b9458"
VECTORS = Path(__file__).resolve().parents[2] / "kadena-core" / "tests" / "vectors" / "testcases.json"


def le(path):
    return b"".join(v.to_bytes(4, "little") for v in path)


def legacy_path(path):
    return bytes([len(path)]) + le(path)


def apdu(ins, p1=0, p2=0, data=b"", cla=0):
    assert len(data) <= 255
    return bytes([cla, ins, p1, p2, len(data)]) + data


def step(a, ui="approve"):
    return {"apdu": a.hex(), "ui": ui}


def modern(ins, payload, path=STD, ui="approve"):
    """@zondax/ledger-js chunking: path with P1=0, 250-byte chunks, the last P1=2."""
    steps = [step(apdu(ins, 0, 0, le(path)), ui)]
    chunks = [payload[i:i + 250] for i in range(0, len(payload), 250)] or [b""]
    for i, c in enumerate(chunks):
        steps.append(step(apdu(ins, 2 if i == len(chunks) - 1 else 1, 0, c), ui))
    return steps


def legacy(ins, payload, ui="approve"):
    """hw-app-alamgu `sendChunks`: 230-byte slices, P1=P2=0."""
    return [step(apdu(ins, 0, 0, payload[i:i + 230]), ui) for i in range(0, len(payload), 230)]


def legacy_json(json_bytes, path=STD, ui="approve"):
    return legacy(0x03, len(json_bytes).to_bytes(4, "little") + json_bytes + legacy_path(path), ui)


FIELDS = ["recipient", "recipient_chain", "network", "amount", "namespace", "module",
          "gas_price", "gas_limit", "creation_time", "chain_id", "nonce", "ttl"]


def transfer_body(tx_type, f):
    b = bytes([tx_type])
    for k in FIELDS:
        v = f[k].encode() if isinstance(f[k], str) else f[k]
        b += bytes([len(v)]) + v
    return b


RCPT = "83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"
NONCE1 = "2022-10-13 07:56:50.893257 UTC"
NONCE2 = "2022-10-14 04:41:03.193557 UTC"
T1 = dict(recipient=RCPT, recipient_chain="0", network="testnet04", amount="1.23", namespace="", module="",
          gas_price="1.0e-6", gas_limit="2300", creation_time="1665647810", chain_id="0", nonce=NONCE1, ttl="600")
NS42 = dict(T1, network="testnet040000000", amount="1.233333333333333333333333333333",
            namespace="n_e595727b657fbbb3b8e362a05a7bb8d12865c1ff", module="kb-USDC",
            gas_price="1.011111111111111e-6", gas_limit="0123456789", creation_time="9876543210",
            ttl="60000000000000000000")
CREATE = dict(T1, amount="23.67", chain_id="1", creation_time="1665722463", nonce=NONCE2)
XCHAIN = dict(CREATE, recipient_chain="2")
XMAX = dict(NS42, recipient_chain="19")
ZEMU_TRANSFERS = [("transfer_1", 0, T1), ("transfer_namespace_42", 0, NS42), ("transfer_create_1", 1, CREATE),
                  ("transfer_cross_chain_1", 2, XCHAIN), ("transfer_cross_chain_max", 2, XMAX)]
HANDLER = dict(NS42, namespace="testnamespace012", module="testmoduletestmoduletestmodule01")
HANDLER_CASES = [("handler_legacy_len_287", HANDLER), ("handler_legacy_len_285", dict(HANDLER, gas_limit="01234567")),
                 ("handler_legacy_len_284", dict(HANDLER, gas_limit="0123456"))]
R3_WF = dict(recipient="a" * 64, recipient_chain="0", network="mainnet01", amount="1.0", namespace="", module="",
             gas_price="1.0e-6", gas_limit="600", creation_time="0", chain_id="0", nonce="n", ttl="28800")

SIMPLE_TRANSFER_C = ('{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\\" \\"9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\\" 11.0)"}},'
                   '"signers":[{"pubKey":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","clist":[{"args":[],"name":"coin.GAS"},{"args":["83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42",11],"name":"coin.TRANSFER"}]}],'
                   '"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"},"nonce":"\\"2021-10-12T03:27:53.700Z\\""}')
C_KEY = "83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"
SIMPLE_TRANSFER = SIMPLE_TRANSFER_C.replace(C_KEY, EXPECTED_PK)
FROM = EXPECTED_PK
CODE = '(coin.transfer \\"' + FROM + '\\" \\"9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\\" 11.0)'
ZMETA = '{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"' + FROM + '"}'


def zneg(clist, meta=ZMETA):
    return ('{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"' + CODE + '"}},"signers":[{"pubKey":"'
            + FROM + '","clist":[' + clist + ']}],"meta":' + meta + ',"nonce":"nonce"}')


LEGACY_BLOBS = [
    ("204", '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":""}},"signers":[{"pubKey":"0123","clist":[{"args":["1","2",0],"name":"coin.TRANSFER"}]}],"meta":{"ttl":0,"gasLimit":0,"gasPrice":0},"nonce":""}', STD),
    ("205", '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":""}},"signers":[{"pubKey":"01234","clist":[{"args":["1","2",0],"name":"coin.TRANSFER"}]}],"meta":{"ttl":0,"gasLimit":0,"gasPrice":0},"nonce":""}', STD),
    ("206", '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":""}},"signers":[{"pubKey":"012345","clist":[{"args":["1","2",0],"name":"coin.TRANSFER"}]}],"meta":{"ttl":0,"gasLimit":0,"gasPrice":0},"nonce":""}', STD),
    ("217", '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":""}},"signers":[{"pubKey":"01234567890123456","clist":[{"args":["1","2",0],"name":"coin.TRANSFER"}]}],"meta":{"ttl":0,"gasLimit":0,"gasPrice":0},"nonce":""}', STD[:2]),
    ("218", '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":""}},"signers":[{"pubKey":"012345678901234567","clist":[{"args":["1","2",0],"name":"coin.TRANSFER"}]}],"meta":{"ttl":0,"gasLimit":0,"gasPrice":0},"nonce":""}', STD[:2]),
    ("435", '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":""}},"signers":[{"pubKey":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff834","clist":[{"args":["1","2",0],"name":"coin.GAS"},{"args":["1","2",11],"name":"coin.TRANSFER"}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff834"},"nonce":"\\"2021-10-12T03:27:53.700Z\\""}', STD),
]

HASH_1 = bytes.fromhex("ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c")
HASH_2 = bytes.fromhex("ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c")  # hash_2 is hash_1 in base64url


def rekey(blob: bytes, pk=EXPECTED_PK) -> bytes:
    """A C fixture with its first signer's key replaced everywhere by `pk`."""
    old = json.loads(blob)["signers"][0]["pubKey"].encode()
    return blob.replace(old, pk.encode())


def signers_cmd(signers, meta=None, tail=""):
    meta = meta or ('{"creationTime":0,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-6,"sender":"k:'
                    + EXPECTED_PK + '"}')
    return ('{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer)"}},"signers":' + signers
            + ',"meta":' + meta + ',"nonce":"n"}' + tail).encode()


def xfer(frm, amount="1.0", to="k:" + "a" * 64):
    return '{"args":["' + frm + '","' + to + '",' + amount + '],"name":"coin.TRANSFER"}'


def entry(pk, clist=None):
    return '{"pubKey":"' + pk + '"' + ('' if clist is None else ',"clist":' + clist) + '}'


def signer_cmd(arg0):
    """R3 #4: a transfer whose sender argument is `arg0`, signed by the device key."""
    meta = '{"creationTime":0,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-6,"sender":"k:' + EXPECTED_PK + '"}'
    clist = '[{"args":["' + arg0 + '","k:' + "b" * 64 + '",1.0],"name":"coin.TRANSFER"},{"args":[],"name":"coin.GAS"}]'
    return ('{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer)"}},'
            '"signers":[{"pubKey":"' + EXPECTED_PK + '","clist":' + clist + '}],"meta":' + meta + ',"nonce":"n"}')


def cases():
    out = []

    def add(name, steps, tag=None, session="default", markers=None):
        markers = list(markers or [])
        if any(bytes.fromhex(s["apdu"])[1] in (0x22, 0x03) for s in steps):
            markers += [m for m in ("WARNING", "CAUTION") if m not in markers]
        out.append({"name": name, "steps": steps, "tag": tag, "session": session, "markers": markers})

    # --- dispatcher, version, addresses -----------------------------------
    add("version modern", [step(apdu(0x20))], "VERSION")
    add("version legacy", [step(apdu(0x00, data=b"\0"))], "VERSION")
    add("bad CLA", [step(apdu(0x20, cla=0x80))])
    add("CLA E0 other INS", [step(apdu(0x20, cla=0xE0))])
    add("device info E0 01", [step(apdu(0x01, cla=0xE0))])
    for ins in (0x05, 0x11, 0x25, 0x55, 0xFE):
        add(f"unknown INS {ins:#x}", [step(apdu(ins))])
    add("V6 INS 0xFF", [step(apdu(0xFF))], None)
    for name, path in (("std", STD), ("acct 5", ALT), ("tail 7/8/9", [H | 44, H | 626, 7, 8, 9]),
                       ("tail hardened", [H | 44, H | 626, H | 1, H | 2, H | 3])):
        add(f"0x21 addr {name}", [step(apdu(0x21, 0, 0, le(path)))])
    add("0x21 extra bytes", [step(apdu(0x21, 0, 0, le(STD) + b"\xde\xad"))])
    add("0x21 short path", [step(apdu(0x21, 0, 0, le(STD)[:19]))])
    add("0x21 empty", [step(apdu(0x21))])
    for name, path in (("purpose 45", [H | 45, H | 626, H, 0, 0]), ("coin 60", [H | 44, H | 60, H, 0, 0]),
                       ("unhardened purpose", [44, H | 626, H, 0, 0])):
        add(f"0x21 bad {name}", [step(apdu(0x21, 0, 0, le(path)))])
    add("Zemu show address", [step(apdu(0x21, 1, 0, le(STD)), "approve")])
    add("Zemu show address reject", [step(apdu(0x21, 1, 0, le(STD)), "reject")])
    add("0x21 show address P1=0xFF", [step(apdu(0x21, 0xFF, 0, le(ALT)), "approve")])
    add("legacy show address", [step(apdu(0x01, 0, 0, legacy_path(STD)), "approve")])
    add("legacy show address reject", [step(apdu(0x01, 0, 0, legacy_path(STD)), "reject")])
    for qty in (5, 4, 3, 2):
        add(f"0x02 qty {qty}", [step(apdu(0x02, 0, 0, legacy_path(STD[:qty])))])
    std_lp = legacy_path(STD)
    for name, data in (("qty 63", b"\x3f" + std_lp[1:]), ("qty 6", b"\x06" + std_lp[1:] + b"\0" * 4),
                       ("qty 1", b"\x01" + std_lp[1:5]), ("qty 0", b"\x00"), ("empty", b""),
                       ("truncated", b"\x05" + std_lp[1:13]), ("extra byte", std_lp + b"\0"),
                       ("bad prefix", legacy_path([H | 44, H | 1, H, 0, 0]))):
        add(f"0x02 {name}", [step(apdu(0x02, 0, 0, data))])
        add(f"0x01 {name}", [step(apdu(0x01, 0, 0, data), "approve")])
    add("Zemu HD-path guard sequence", [step(apdu(0x02, 0, 0, b"\x3f" + std_lp[1:])),
                                        step(apdu(0x02, 0, 0, b"\x06" + std_lp[1:] + b"\0" * 4)),
                                        step(apdu(0x02, 0, 0, b"\x01" + std_lp[1:5])),
                                        step(apdu(0x02, 0, 0, std_lp)), step(apdu(0x02, 0, 0, legacy_path(STD[:2]))),
                                        step(apdu(0x20))], "VERSION")
    add("path tail zeroed after qty 5", [step(apdu(0x02, 0, 0, legacy_path([H | 44, H | 626, 1, 2, 3]))),
                                         step(apdu(0x02, 0, 0, legacy_path(STD[:2])))])

    # --- modern JSON 0x22 --------------------------------------------------
    add("Zemu sign json simple_transfer", modern(0x22, SIMPLE_TRANSFER.encode()))
    add("sign json reject", modern(0x22, SIMPLE_TRANSFER.encode(), ui="reject"))
    add("sign json other path", modern(0x22, SIMPLE_TRANSFER.replace(EXPECTED_PK, ALT_PK).encode(), ALT))
    for v in json.loads(VECTORS.read_text()):
        add(f"vector {v['index']} {v['name']}", modern(0x22, rekey(bytes.fromhex(v["blob"]))))
    add("Zemu negative oob_max_items_transfer",
        modern(0x22, zneg(",".join(['{"args":[],"name":"coin.GAS"}'] + ['{"args":["a","b"],"name":"coin.TRANSFER"}'] * 96)).encode()))
    add("Zemu negative oob_max_items_rotate",
        modern(0x22, zneg(",".join(['{"args":[],"name":"coin.GAS"}'] + ['{"args":["a","b"],"name":"coin.ROTATE"}'] * 96)).encode()))
    add("oob_max_items_xchain",
        modern(0x22, zneg(",".join(['{"args":["a","b"],"name":"coin.TRANSFER_XCHAIN"}'] * 96)).encode()))
    add("Zemu negative gas_len_wrap",
        modern(0x22, zneg('{"args":[],"name":"coin.GAS"}', ZMETA.replace('"gasLimit":600', '"gasLimit":"1' + "0" * 300 + '"')).encode()))
    add("Zemu unknown_cap_arg_render", modern(0x22, zneg('{"args":[],"name":"coin.GAS"},{"args":["AB"],"name":"foo.BAR"}').encode()))
    add("init short path", [step(apdu(0x22, 0, 0, le(STD)[:19])), step(apdu(0x22, 1, 0, b"{}"))])
    add("init bad prefix", [step(apdu(0x22, 0, 0, le([H | 44, H | 1, H, 0, 0]))), step(apdu(0x22, 2, 0, b"{}"))])
    add("init extra bytes dropped", [step(apdu(0x22, 0, 0, le(STD) + b"GARBAGE"))] + modern(0x22, SIMPLE_TRANSFER.encode())[1:])
    for ins in (0x22, 0x23, 0x24):
        add(f"{ins:#x} ADD without INIT", [step(apdu(ins, 1, 0, b"{}"))])
        add(f"{ins:#x} LAST without INIT", [step(apdu(ins, 2, 0, b"{}"))])
        add(f"{ins:#x} P1=3", [step(apdu(ins, 3, 0, le(STD)))])
        add(f"{ins:#x} empty LAST", modern(ins, b""))
    add("0x21 closes modern stream", [step(apdu(0x22, 0, 0, le(STD))), step(apdu(0x21, 0, 0, le(STD))),
                                      step(apdu(0x22, 1, 0, b"{}"))])
    add("V8 tx type from LAST ins", [step(apdu(0x24, 0, 0, le(STD)))] + [
        dict(s, apdu=s["apdu"][:2] + "23" + s["apdu"][4:]) for s in modern(0x22, SIMPLE_TRANSFER.encode())[1:-1]] + [
        modern(0x22, SIMPLE_TRANSFER.encode())[-1]], "V8")
    big = SIMPLE_TRANSFER.replace('"data":{}', '"data":{"pad":"PAD"}')
    big = big.replace("PAD", "x" * (15104 - (len(big) - 3)))
    assert len(big) == 15104
    add("max size 15104 bytes", modern(0x22, big.encode()))
    add("overflow 15105 bytes", modern(0x22, (big + " ").encode()))
    for name, body in (("control char", '{"a":\x01}'), ("bad escape", '{"a":"\\q"}'), ("unmatched", "[}"),
                       ("incomplete", '{"a":1'), ("whitespace only", "   "), ("NUL first", "\0{}"),
                       ("missing networkId", SIMPLE_TRANSFER.replace('"networkId"', '"networkIdX"')),
                       ("missing signers", SIMPLE_TRANSFER.replace('"signers"', '"signersX"')),
                       ("missing pubKey", SIMPLE_TRANSFER.replace('"pubKey"', '"pubKeyX"')),
                       ("empty networkId", SIMPLE_TRANSFER.replace('"mainnet01"', '""')),
                       ("cap without args", zneg('{"name":"foo.BAR"}')),
                       ("empty cap name", zneg('{"args":[],"name":""}')),
                       ("meta prefix 4 keys", zneg('{"args":[],"name":"coin.GAS"}', '{"creationTime":0,"ttl":1,"gasLimit":2,"chainId":"0"}')),
                       ("meta out of order", zneg('{"args":[],"name":"coin.GAS"}', '{"ttl":1,"creationTime":0}')),
                       ("clist null", zneg('{"args":[],"name":"coin.GAS"}').replace('"clist":[{"args":[],"name":"coin.GAS"}]', '"clist":null')),
                       ("bytes after NUL", SIMPLE_TRANSFER + "\0trailing{[")):
        add(f"json {name}", modern(0x22, body.encode()))
    token_json = zneg(",".join(['{"args":[],"name":"coin.GAS"}'] * 150))
    add("json 768+ tokens", modern(0x22, token_json.encode()))
    add("json 110+ tokens (Nano X cap)", modern(0x22, zneg(",".join(['{"args":[],"name":"coin.GAS"}'] * 20)).encode()))

    # V3 (R3 #4): same response (the tx signs), but the Unscoped Signer warning must show.
    # The marker is a prefix: NBGL on Nano shortens the title ("Unscop...ner (1/2)").
    add("V3 signer exact", modern(0x22, signer_cmd("k:" + EXPECTED_PK).encode()), markers=["Unscop", "Key not in"])
    add("V3 signer other key", modern(0x22, signer_cmd("k:" + "c" * 64).encode()), markers=["Unscop", "Key not in"])
    add("V3 signer key prefix (R3 #4 attack)", modern(0x22, signer_cmd("k:" + EXPECTED_PK + "ff").encode()), "V3",
        markers=["Unscop", "Key not in"])

    # V4 (R3 #5): duplicate keys.
    add("V4 duplicate networkId", modern(0x22, SIMPLE_TRANSFER.replace('{"networkId":"mainnet01"', '{"networkId":"NET_FIRST","networkId":"NET_SECOND"', 1).encode()), "V4")
    add("V4 duplicate cap name", modern(0x22, zneg('{"args":[],"name":"coin.GAS","name":"coin.TRANSFER"}').encode()), "V4")
    add("V4 duplicate in meta", modern(0x22, SIMPLE_TRANSFER.replace('"chainId":"0"', '"chainId":"3","chainId":"7"').encode()), "V4")
    add("V4 escaped duplicate", modern(0x22, SIMPLE_TRANSFER.replace('{"networkId":"mainnet01"', '{"networkId":"A","networ\\u006bId":"B"', 1).encode()), "V4")
    add("V4 duplicate in exec.data", modern(0x22, SIMPLE_TRANSFER.replace('"data":{}', '"data":{"a":1,"a":2}').encode()), "V4")

    # --- legacy JSON 0x03 --------------------------------------------------
    add("Zemu legacy sign json simple_transfer", legacy_json(SIMPLE_TRANSFER.encode()))
    add("legacy sign json reject", legacy_json(SIMPLE_TRANSFER.encode(), ui="reject"))
    for name, blob, path in LEGACY_BLOBS:
        # V9: these name keys that are not the device's.
        add(f"Zemu test_apdu_legacy_blob_{name}", legacy_json(blob.encode(), path), "V9")
        # The same lengths with the device key as the only, unscoped signer (V11:
        # blind signing ON), the nonce as padding.
        pk = PK2 if len(path) == 2 else EXPECTED_PK
        base = ('{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":""}},"signers":[{"pubKey":"'
                + pk + '"}],"meta":null,"nonce":""}')
        dev = base.replace('"nonce":""', '"nonce":"' + "x" * (len(blob) - len(base)) + '"')
        assert len(dev) == len(blob)
        add(f"legacy blob length {name} (device signer)", legacy_json(dev.encode(), path), session="blind_expert")
    pad = SIMPLE_TRANSFER.replace('"data":{}', '"data":{"p":"PAD"}')
    pad = pad.replace("PAD", "x" * (230 * 5 - 25 - (len(pad) - 3)))
    add("legacy json full last APDU", legacy_json(pad.encode()))
    add("legacy json no length", [step(apdu(0x03, 0, 0, b"\1\0\0"))])
    add("legacy json short buffer", [step(apdu(0x03, 0, 0, (1000).to_bytes(4, "little") + b"{}" + legacy_path(STD)))])
    add("legacy json bad path", legacy_json(b"{}", [H | 44, H | 1, H, 0, 0]))
    add("legacy json extra byte", [step(apdu(0x03, 0, 0, (2).to_bytes(4, "little") + b"{}" + legacy_path(STD) + b"\0"))])
    add("legacy json parse error", legacy_json(b'{"a":'))
    add("legacy json no networkId", legacy_json(SIMPLE_TRANSFER.replace('"networkId"', '"x"').encode()))
    add("V4 legacy json duplicate", legacy_json(SIMPLE_TRANSFER.replace('{"networkId":"mainnet01"', '{"networkId":"a","networkId":"b"', 1).encode()), "V4")

    # --- hash 0x23 / 0x04 (blind signing OFF in the default session) ------
    for session in ("default", "blind_expert"):
        add(f"Zemu sign hash_1 [{session}]", modern(0x23, HASH_1), session=session)
        add(f"hash_1 reject [{session}]", modern(0x23, HASH_1, ui="reject"), session=session)
        add(f"hash 31 bytes [{session}]", modern(0x23, HASH_1[:31]), session=session)
        add(f"hash 33 bytes [{session}]", modern(0x23, HASH_1 + b"\0"), session=session)
        add(f"Zemu legacy sign hash_1 [{session}]", legacy(0x04, HASH_1 + legacy_path(STD)), session=session)
        add(f"legacy hash 2-comp path [{session}]", legacy(0x04, HASH_1 + legacy_path(STD[:2])), session=session)
        add(f"legacy hash bad path [{session}]", legacy(0x04, HASH_1 + legacy_path([H | 44, H | 1, H])), session=session)
    add("json in expert mode", modern(0x22, SIMPLE_TRANSFER.encode()), session="blind_expert")
    add("transfer in expert mode", modern(0x24, transfer_body(0, T1)), session="blind_expert")
    add("show address in expert mode", [step(apdu(0x21, 1, 0, le(STD)))], session="blind_expert")

    # --- structured transfer 0x24 / 0x10 ----------------------------------
    for name, t, f in ZEMU_TRANSFERS:
        add(f"Zemu sign transfer {name}", modern(0x24, transfer_body(t, f)))
        add(f"Zemu legacy transfer {name}", legacy(0x10, legacy_path(STD) + transfer_body(t, f)))
    for name, f in HANDLER_CASES:
        add(f"Zemu {name}", legacy(0x10, legacy_path(STD) + transfer_body(0, f)))
    add("transfer reject", modern(0x24, transfer_body(0, T1), ui="reject"))
    add("legacy transfer reject", legacy(0x10, legacy_path(STD) + transfer_body(0, T1), ui="reject"))
    add("transfer tx_type 3", modern(0x24, transfer_body(3, T1)))
    add("legacy transfer tx_type 3", legacy(0x10, legacy_path(STD) + transfer_body(3, T1)))
    body = transfer_body(0, T1)
    add("transfer truncated", modern(0x24, body[:-1]))
    add("transfer trailing byte", modern(0x24, body + b"\0"))
    add("transfer recipient 63", modern(0x24, transfer_body(0, dict(T1, recipient="a" * 63))))
    caps = dict(recipient_chain=2, network=20, amount=32, namespace=63, module=32, gas_price=20, gas_limit=10,
                creation_time=12, chain_id=2, nonce=32, ttl=20)
    for k, cap in caps.items():
        fill = {"namespace": "s", "module": "m", "nonce": "o", "network": "n"}.get(k, "1")
        add(f"transfer {k} at cap", modern(0x24, transfer_body(2, dict(T1, **{k: fill * cap}))))
        add(f"transfer {k} over cap", modern(0x24, transfer_body(2, dict(T1, **{k: fill * (cap + 1)}))))
    # V2 (R3 #3) injections and allowlist refusals.
    for name, field, value in (("nonce injection (R3)", "nonce", 'x","injected":"HID'),
                               ("amount injection (R3)", "amount", '1,"evil":9'),
                               ("recipient injection (R3)", "recipient", 'a","x":"' + "a" * 56),
                               ("namespace injection (R3)", "namespace", 'a","b":"c'),
                               ("network with space", "network", "net 01"),
                               ("negative amount", "amount", "-1"),
                               ("module paren", "module", "m)"),
                               ("ttl comma", "ttl", "600,"),
                               ("chain id letter", "chain_id", "a")):
        f = dict(T1, **{field: value})
        if field == "namespace":
            f["module"] = "m"
        add(f"V2 {name}", modern(0x24, transfer_body(0, f)), "V2")
        add(f"V2 legacy {name}", legacy(0x10, legacy_path(STD) + transfer_body(0, f)), "V2")
    # V1 (R3 F-A): primer + short final item.
    body = legacy_path(STD[:3]) + b"\0"
    for k in FIELDS[:11]:
        v = R3_WF[k].encode()
        body += bytes([len(v)]) + v
    body += bytes([20])
    attack = apdu(0x10, 0, 0, body)
    primer_data = bytearray(b"A" * (len(attack) + 20 - 5))
    primer_data[len(attack) - 5:] = b"99999999999999999999"
    add("V1 R3 F-A primer + short ttl", [step(apdu(0x20, 0, 0, bytes(primer_data))), step(attack)], "V1")
    # V1 (R3 F-B): module item split in a 210-byte APDU.
    b1 = legacy_path(STD[:3]) + b"\0"
    for v in ("a" * 64, "00", "n" * 20, "1" + "0" * 31, "n" * 63):
        b1 += bytes([len(v)]) + v.encode()
    b1 += bytes([32]) + b"LEAD"
    b2 = b"TAL"
    for v in ("1.0e-6", "600", "0", "0", "nn", "28800"):
        b2 += bytes([len(v)]) + v.encode()
    add("V1 R3 F-B 205/210 split", [step(apdu(0x20, 0, 0, b"B" * 230)), step(apdu(0x10, 0, 0, b1)), step(apdu(0x10, 0, 0, b2))], "V1")
    add("legacy transfer no tx_type", [step(apdu(0x10, 0, 0, legacy_path(STD)))])
    add("legacy transfer no items", [step(apdu(0x10, 0, 0, legacy_path(STD) + b"\0"))])
    add("legacy transfer 13 items", [step(apdu(0x10, 0, 0, legacy_path(STD) + b"\0" + b"\x011" * 13))])
    add("legacy transfer bad path", [step(apdu(0x10, 0, 0, b"\x06" + legacy_path(STD)[1:] + b"\0"))])

    # --- V5: one streaming state ------------------------------------------
    first03 = apdu(0x03, 0, 0, (1000).to_bytes(4, "little") + b" " * 226)
    add("V5 legacy first chunk then modern ADD", [step(apdu(0x22, 0, 0, le(STD))), step(first03),
                                                  step(apdu(0x22, 1, 0, b"{}")), step(apdu(0x22, 2, 0, b"{}"))], "V5")
    add("V5 open 0x03 then 0x04", [step(first03), step(apdu(0x04, 0, 0, HASH_1 + legacy_path(STD)))], "V5")
    add("V5 open 0x03 then modern ADD", [step(first03), step(apdu(0x22, 1, 0, b"xx"))], "V5")
    add("V8 modern INS mixing", [step(apdu(0x22, 0, 0, le(STD))), step(apdu(0x24, 1, 0, b"{")),
                                 step(apdu(0x22, 2, 0, b"{}"))], "V8")
    for first in (0x22, 0x23, 0x24):
        for second in (0x22, 0x23, 0x24):
            if first != second:
                for p1 in (1, 2):
                    add(f"V8 {first:#x} stream, {second:#x} P1={p1}",
                        [step(apdu(first, 0, 0, le(STD))), step(apdu(second, p1, 0, b"\x5a" * 32)),
                         step(apdu(first, 2, 0, b"\x5a" * 32))], "V8")
    for session in ("default", "blind_expert"):
        add(f"V8 0x22 stream finished with 0x23 [{session}]",
            [step(apdu(0x22, 0, 0, le(STD))), step(apdu(0x23, 2, 0, b"\x5a" * 32))], "V8", session=session)
    lt = legacy_path(STD) + transfer_body(0, T1)
    lh = legacy_path(STD) + transfer_body(0, HANDLER)
    add("V8 legacy 0x03 open then 0x10", [step(first03), step(apdu(0x10, 0, 0, lt)), step(apdu(0x10, 0, 0, lt))], "V8")
    add("V8 legacy 0x10 open then 0x03", [step(apdu(0x10, 0, 0, lh[:230])), step(first03),
                                          step(apdu(0x10, 0, 0, lh[230:]))], "V8")
    # V7: a legacy 0x02 between INIT and LAST. The first two steps return both
    # public keys so that compare.py can check which key signed.
    add("V7 0x02 between INIT and LAST",
        [step(apdu(0x21, 0, 0, le(STD))), step(apdu(0x02, 0, 0, legacy_path(ALT))),
         step(apdu(0x22, 0, 0, le(STD))), step(apdu(0x02, 0, 0, legacy_path(ALT)))]
        + modern(0x22, SIMPLE_TRANSFER.encode())[1:], "V7")

    # --- fuzz: deterministic mutations of valid inputs --------------------
    # --- V9 .. V13 ----------------------------------------------------------
    D = EXPECTED_PK
    add("V9 Zemu simple transfer (C signer key)", modern(0x22, SIMPLE_TRANSFER_C.encode()), "V9")
    add("V9 legacy Zemu simple transfer (C signer key)", legacy_json(SIMPLE_TRANSFER_C.encode()), "V9")
    for name, signers in (
            ("P2 duplicate device entry", "[" + entry(D, "[" + xfer("k:" + D) + "]") + ","
             + entry(D, "[" + xfer("k:" + D, "1000.0") + "]") + "]"),
            ("device key twice, other case", "[" + entry(D, "[" + xfer("k:" + D) + "]") + ","
             + entry(D.upper(), "[]") + "]"),
            ("device key as addr of another entry", "[" + entry(D, "[" + xfer("k:" + D) + "]") + ","
             + '{"pubKey":"' + "a" * 64 + '","scheme":"WebAuthn","addr":"' + D + '"}]'),
            ("device key absent", "[" + entry("a" * 64, "[" + xfer("k:" + D) + "]") + "]"),
            ("escaped key name", "[" + entry(D, "[" + xfer("k:" + D) + "]") + ',{"pub\\u004bey":"' + D + '"}]')):
        for session in ("default", "blind_expert"):
            add(f"V9 {name} [{session}]", modern(0x22, signers_cmd(signers)), "V9", session=session)
    second = "[" + entry("a" * 64, '[{"args":[],"name":"coin.GAS"}]') + "," + entry(D, "[" + xfer("k:" + D, "1000.0") + "]") + "]"
    add("V9 device entry second", modern(0x22, signers_cmd(second)), "V9", markers=["Signers"])
    p1 = "[" + entry(D, "[]") + "," + entry("a" * 64, "[" + xfer("k:" + D, "1000.0") + "]") + "]"
    for session in ("default", "blind_expert"):
        add(f"V10 P1 empty clist beside another signer [{session}]", modern(0x22, signers_cmd(p1)), "V10",
            session=session, markers=["Unscop", "Signers"])
        add(f"V10 empty clist [{session}]", modern(0x22, signers_cmd("[" + entry(D, "[]") + "]")), "V10",
            session=session, markers=["Unscop"])
        add(f"V11 no clist [{session}]", modern(0x22, signers_cmd("[" + entry(D) + "]")), "V11", session=session)
        add(f"V11 legacy no clist [{session}]", legacy_json(signers_cmd("[" + entry(D) + "]")), "V11",
            session=session)
        add(f"V11 meta null [{session}]",
            modern(0x22, signers_cmd("[" + entry(D, "[" + xfer("k:" + D) + "]") + "]", meta="null")), "V11",
            session=session)
    for name, tail in (("object after the value", "{}"), ("text after the value", " x"),
                       ("NUL then bytes", '\0{"a":1}')):
        add(f"V12 {name}", modern(0x22, signers_cmd("[" + entry(D, "[" + xfer("k:" + D) + "]") + "]", tail=tail)), "V12")
        add(f"V12 legacy {name}",
            legacy_json(signers_cmd("[" + entry(D, "[" + xfer("k:" + D) + "]") + "]", tail=tail)), "V12")
    for name, ch, shown in (("C1 control", "\u0085", "\\xC2\\x85"), ("NBSP", "\u00a0", "\\xC2\\xA0"),
                            ("soft hyphen", "\u00ad", "\\xC2\\xAD")):
        tx = signers_cmd("[" + entry(D, "[" + xfer("k:" + D, to="k:bob" + ch) + "]") + "]")
        add(f"V13 {name} in an account", modern(0x22, tx), "V13", markers=["k:bob" + shown])
    for name, field, value in (("uppercase recipient", "recipient", "A" * 64),
                               ("amount lone dot", "amount", "."),
                               ("amount empty", "amount", ""),
                               ("gas price lone e", "gas_price", "e"),
                               ("gas price lone plus", "gas_price", "+"),
                               ("ttl empty", "ttl", ""),
                               ("chain id empty", "chain_id", "")):
        f = dict(T1, **{field: value})
        add(f"V2 {name}", modern(0x24, transfer_body(0, f)), "V2")
        add(f"V2 legacy {name}", legacy(0x10, legacy_path(STD) + transfer_body(0, f)), "V2")
    add("V2 cross-chain empty recipient chain", modern(0x24, transfer_body(2, dict(XCHAIN, recipient_chain=""))), "V2")

    # --- V14 .. V18 (round 2) -------------------------------------------------
    rotate = ('{"networkId":"mainnet01","payload":{"exec":{"data":{"new":{"keys":["attacker"],"pred":"keys-all"}},'
              '"code":"(coin.rotate \\"alice\\" (read-keyset \\"new\\"))"}},"signers":['
              + entry(D, '[{"args":[],"name":"coin.GAS"},{"args":["alice"],"name":"coin.ROTATE"}]')
              + '],"meta":{"creationTime":0,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-6,"sender":"k:'
              + D + '"},"nonce":"n"}').encode()
    for session in ("default", "blind_expert"):
        add(f"V14 rotation [{session}]", modern(0x22, rotate), "V14", session=session, markers=["new owner"])
        add(f"V14 legacy rotation [{session}]", legacy_json(rotate), "V14", session=session, markers=["new owner"])
    gas = ('{"creationTime":0,"ttl":28800,"gasLimit":150000,"chainId":"0","gasPrice":1e+2,"sender":"k:' + D + '"}')
    add("V15 exponent gas price", modern(0x22, signers_cmd("[" + entry(D, "[" + xfer("k:" + D) + "]") + "]", meta=gas)),
        "V15", markers=["15000000"])
    add("V15 structured transfer exponent gas price",
        modern(0x24, transfer_body(0, dict(T1, gas_price="1e+2", gas_limit="150000"))), "V15", markers=["15000000"])
    add("V16 vanity receiver", modern(0x22, signers_cmd("[" + entry(D, "[" + xfer("k:" + D, to="bob") + "]") + "]")),
        "V16", markers=["principal"])
    add("V20 other module capability",
        modern(0x22, signers_cmd("[" + entry(D, '[{"args":["a"],"name":"free.evil.X"}]') + "]")), "V20",
        markers=["can use this"])
    add("V19 expert validity window", modern(0x22, signers_cmd("[" + entry(D, "[" + xfer("k:" + D) + "]") + "]")),
        "V19", session="blind_expert", markers=["unix time", "TTL (sec"])
    # V18: escaped keys (the C v1.3.1 review's A1-A4, A8) and nested literal duplicates (V4).
    # "EU" below stands for the two bytes backslash-u in the JSON (a JSON escape).
    gas_cap = '{"args":[],"name":"coin.GAS"}'
    rot_code = '(coin.rotate \\"alice\\" (read-keyset \\"new\\"))'
    t1 = xfer("k:" + D)
    t1000 = xfer("k:" + D, "1000.0")

    def key_cmd(code, clist, before_meta=""):
        return ('{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"' + code + '"}},"signers":['
                + entry(D, clist) + '],' + before_meta + '"meta":{"creationTime":0,"ttl":28800,"gasLimit":600,'
                '"chainId":"0","gasPrice":1.0e-6,"sender":"k:' + D + '"},"nonce":"n"}').replace("EU", BS + "u").encode()
    code1000 = '(coin.transfer \\"k:' + D + '\\" \\"k:' + "a" * 64 + '\\" 1000.0)'
    code1 = code1000.replace("1000.0", "1.0")
    control = key_cmd(code1, "[" + t1 + "," + gas_cap + "]")
    attacks = {
        "A1 escaped name key": key_cmd(code1000, '[{"nEU0061me":"coin.TRANSFER","args":["k:' + D + '","k:' + "a" * 64
                                       + '",1000.0],"name":"coin.GAS"},' + gas_cap + ']'),
        "A2 escaped signers": control.replace(b'"signers":', ('"signEU0065rs":[' + entry(D, "[" + t1000 + "," + gas_cap
                                                                                         + "]") + '],"signers":')
                                              .replace("EU", BS + "u").encode(), 1),
        "A3 escaped ROTATE name": key_cmd(rot_code, "[" + gas_cap + ',{"args":["alice"],"name":"coin.EU0052OTATE"}]'),
        "A4 escaped name key hides ROTATE": key_cmd(rot_code, "[" + gas_cap
                                                    + ',{"nEU0061me":"coin.ROTATE","args":["alice"],"name":"coin.GAS"}]'),
        "A8 escaped meta": key_cmd(code1, "[" + t1 + "," + gas_cap + "]",
                                   '"mEU0065ta":{"creationTime":1634009214,"ttl":28800,"gasLimit":150000,"chainId":"0",'
                                   '"gasPrice":0.1,"sender":"k:' + D + '"},'),
    }
    for name, tx in attacks.items():
        assert BS.encode() + b"u" in tx
        add(f"V18 {name}", modern(0x22, tx), "V18")
        add(f"V18 legacy {name}", legacy_json(tx), "V18")
    add("V18 control", modern(0x22, control))
    add("V4 duplicate name in a clist entry",
        modern(0x22, control.replace(gas_cap.encode(), b'{"name":"coin.GAS","args":[],"name":"coin.TRANSFER"}', 1)), "V4")
    add("V4 duplicate clist in the signer entry",
        modern(0x22, control.replace(('{"pubKey":"' + D + '","clist":').encode(),
                                     ('{"pubKey":"' + D + '","clist":[' + gas_cap + '],"clist":').encode(), 1)), "V4")

    # --- V20, V21, V15 integers, verifiers (round 3) --------------------------------
    debit_code = ('(install-capability (coin.TRANSFER \\"k:' + D + '\\" \\"k:' + "a" * 64 + '\\" 1000.0)) '
                  '(coin.transfer \\"k:' + D + '\\" \\"k:' + "a" * 64 + '\\" 1000.0)')

    def r3_cmd(cap, meta=None):
        meta = meta or ('{"creationTime":0,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-6,"sender":"k:'
                        + D + '"}')
        return ('{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"' + debit_code + '"}},"signers":['
                + entry(D, '[{"name":"coin.GAS","args":[]},' + cap + ']') + '],"meta":' + meta
                + ',"nonce":"r3"}').encode()
    for name, cap in (("DEBIT", '{"name":"coin.DEBIT","args":["k:' + D + '"]}'),
                      ("CREDIT", '{"name":"coin.CREDIT","args":["k:' + D + '"]}')):
        for session in ("default", "blind_expert"):
            add(f"V20 coin.{name} [{session}]", modern(0x22, r3_cmd(cap)), "V20", session=session,
                markers=["not verified"])
            add(f"V20 legacy coin.{name} [{session}]", legacy_json(r3_cmd(cap)), "V20", session=session,
                markers=["not verified"])
    add("V21 exponent amount", modern(0x22, r3_cmd(xfer("k:" + D, "1.0000000001e3"))), "V21")
    add("V21 legacy exponent amount", legacy_json(r3_cmd(xfer("k:" + D, "1.0000000001e3"))), "V21")
    add("V21 control", modern(0x22, r3_cmd(xfer("k:" + D, "1000.0000001"))))
    add("V15 fractional gas limit", modern(0x22, r3_cmd(xfer("k:" + D), meta='{"creationTime":0,"ttl":28800,'
        '"gasLimit":1.5,"chainId":"0","gasPrice":1000.0,"sender":"k:' + D + '"}')), "V15")
    add("V22 verifiers", modern(0x22, r3_cmd(xfer("k:" + D)).replace(b'"nonce":"r3"}',
                                                                    b'"nonce":"r3","verifiers":[]}')), "V22")

    # --- V23 (token structured transfers), V24 (bare amounts) (round 4) -------------
    for name, t, f in ZEMU_TRANSFERS:
        if f["namespace"]:
            add(f"V23 token transfer {name} [blind_expert]", modern(0x24, transfer_body(t, f)), "V23",
                session="blind_expert", markers=["WARNING", "not verified"])
            add(f"V23 legacy token transfer {name} [blind_expert]", legacy(0x10, legacy_path(STD) + transfer_body(t, f)),
                "V23", session="blind_expert", markers=["WARNING", "not verified"])
    for name, amount in (("escaped decimal", r'{"decimal":"1\u0030\u0030\u0030.0"}'),
                         ("decimal exponent", '{"decimal":"1e3"}'), ("decimal negative", '{"decimal":"-1.0"}'),
                         ("decimal leading zero", '{"decimal":"01.0"}'), ("decimal empty", '{"decimal":""}'),
                         ("decimal leading dot", '{"decimal":".5"}'), ("decimal trailing dot", '{"decimal":"1."}'),
                         ("decimal number", '{"decimal":1000.0}'), ("decimal extra key", '{"decimal":"1000.0","x":1}'),
                         ("decimal nested", '{"decimal":{"decimal":"1000.0"}}'),
                         ("string", '"1000.0"'), ("int object", '{"int":1000}'), ("negative", "-1.0"),
                         ("leading zero", "01.0"), ("trailing dot", "1.")):
        add(f"V24 {name} amount", modern(0x22, r3_cmd(xfer("k:" + D, amount))), "V24")
        add(f"V24 legacy {name} amount", legacy_json(r3_cmd(xfer("k:" + D, amount))), "V24")
    add("V24 unquoted decimal key amount", modern(0x22, r3_cmd(xfer("k:" + D, '{decimal:"1.5"}'))), "V24")
    # --- V25 (12 places), V26 (structured amount with a fraction) (round 5) ---------
    for name, amount in (("13 places", "1.1234567890123"), ("decimal 13 places", '{"decimal":"1.1234567890123"}'),
                         ("256 places", "0." + "9" * 256)):
        add(f"V25 {name} amount", modern(0x22, r3_cmd(xfer("k:" + D, amount))), "V25")
        add(f"V25 legacy {name} amount", legacy_json(r3_cmd(xfer("k:" + D, amount))), "V25")
    add("V25 control 12 places", modern(0x22, r3_cmd(xfer("k:" + D, "1.123456789012"))))
    add("V25 control decimal 12 places", modern(0x22, r3_cmd(xfer("k:" + D, '{"decimal":"1.123456789012"}'))))
    add("V25 structured 13 places", modern(0x24, transfer_body(0, dict(T1, amount="1.1234567890123"))), "V25")
    add("V25 legacy structured 13 places", legacy(0x10, legacy_path(STD) + transfer_body(0, dict(T1, amount="1.1234567890123"))),
        "V25")
    add("V25 structured control 12 places", modern(0x24, transfer_body(0, dict(T1, amount="1.123456789012"))))
    add("V26 structured integer amount", modern(0x24, transfer_body(0, dict(T1, amount="1000"))), "V26")
    add("V26 legacy structured integer amount", legacy(0x10, legacy_path(STD) + transfer_body(0, dict(T1, amount="1000"))),
        "V26")
    add("V24 control decimal object", modern(0x22, r3_cmd(xfer("k:" + D, '{"decimal":"231"}'))))
    add("V24 legacy control decimal object", legacy_json(r3_cmd(xfer("k:" + D, '{"decimal":"231"}'))))
    add("V24 control", modern(0x22, r3_cmd(xfer("k:" + D, "1000.0"))))

    rng = random.Random(20260928)
    seeds = [SIMPLE_TRANSFER.encode()] + [rekey(bytes.fromhex(v["blob"])) for v in json.loads(VECTORS.read_text())[:8]]
    for i in range(60):
        s = bytearray(rng.choice(seeds))
        kind = rng.choice(["flip", "delete", "insert", "truncate", "dup"])
        pos = rng.randrange(len(s))
        if kind == "flip":
            s[pos] = rng.choice(b'{}[]",:\\ \x00\x01\xff0aZ')
        elif kind == "delete":
            del s[pos:pos + rng.randint(1, 8)]
        elif kind == "insert":
            s[pos:pos] = rng.choice([b'"', b"}", b",", b'"x":1,', b"\\u00", b"\x80"])
        elif kind == "truncate":
            s = s[:pos]
        else:
            s[pos:pos] = s[max(0, pos - 30):pos]
        add(f"fuzz json {i} ({kind}@{pos})", modern(0x22, bytes(s)), "FUZZ")
    for i in range(40):
        t, f = rng.choice([(0, T1), (1, CREATE), (2, XCHAIN), (0, NS42)])
        b = bytearray(transfer_body(t, f))
        kind = rng.choice(["flip", "len", "truncate", "extend"])
        pos = rng.randrange(len(b))
        if kind == "flip":
            b[pos] = rng.randrange(256)
        elif kind == "len":
            b[pos] = rng.choice([0, 1, 2, 31, 32, 33, 63, 64, 65, 255])
        elif kind == "truncate":
            b = b[:pos]
        else:
            b += bytes(rng.randrange(256) for _ in range(rng.randint(1, 5)))
        which = rng.choice(["modern", "legacy"])
        steps = modern(0x24, bytes(b)) if which == "modern" else legacy(0x10, legacy_path(STD) + bytes(b))
        add(f"fuzz transfer {i} ({which} {kind}@{pos})", steps, "FUZZ")
    return out


if __name__ == "__main__":
    cs = cases()
    print(len(cs), "cases,", sum(len(c["steps"]) for c in cs), "APDUs")
