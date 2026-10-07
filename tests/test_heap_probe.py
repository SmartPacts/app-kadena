"""Heap measurement, on the measurement app built by tools/heap-probe.sh (never
shipped); skipped on the normal app, which refuses INS 0xFE.

The largest review the app accepts (`largest` in test_review_scope.py: values at
their display bounds, as many transfers as the device takes), with printable
From/To and with every From/To byte non-printable (shown as \\xNN), is reviewed and
approved; the app then reports the most heap bytes in use at any moment of it, as
the allocator counts them (headers and alignment included), and the number of
allocations that failed. The figures are printed as HEAP lines and recorded in
submission/SECURITY-AUDIT.md.
"""

import struct

import pytest
from kadena import EXPECTED_PK, SW_OK, apdu, blake2b, verify
from test_review_scope import largest, send_last

PROBE = apdu(0xFE)


def probe(kda):
    sw, data = kda.send(PROBE)
    if sw != SW_OK:
        pytest.skip("not the heap measurement app")
    assert len(data) == 12
    return struct.unpack(">III", data)


@pytest.mark.parametrize("fill", ["x", "\u00a0"], ids=["printable", "nonprintable"])
def test_heap_peak_of_the_largest_review(kda, device, fill):
    probe(kda)  # starts the measurement from the bytes in use now
    tx = largest(device, fill)
    assert len(tx) <= 15104
    with kda.pending(send_last(kda, tx), no_tick_timeout=True):
        kda.approve_tx(timeout=3600)
    sw, sig = kda.result()
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(tx), sig)
    size, peak, failed = probe(kda)
    print(f"HEAP {device.name} {fill.encode().hex()} size={size} peak={peak} headroom={size - peak} failed={failed}")
    assert failed == 0
    assert peak < size
