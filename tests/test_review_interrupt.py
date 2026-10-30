"""A command sent while a review is on screen.

The SDK answers any command that arrives while a previous one awaits its reply with
a bare 0x6901, before the app sees it; the review stays on screen, and approving it
signs exactly what an undisturbed review of the same transaction signs.

In the emulator a reply goes to every request waiting at that moment, so the
signing request itself receives the 0x6901 meant for the intruding command, and
the approved signature that follows has no request left to receive it. Speculos
also forwards every reply the device sends to a client of its raw APDU port, so a
listener there records the replies as the device sent them, the signature
included.
"""

import socket
import time

from kadena import EXPECTED_PK, SIMPLE_TRANSFER, STD, SW_OK, apdu, blake2b, le, modern_chunks, verify

REFUSED = bytes.fromhex("6901")


class ReplyListener:
    """Records the device's replies from Speculos's raw APDU port (each framed as
    a 4-byte length of the data, then the data and the status word)."""

    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.buf = b""

    def replies(self, count, timeout):
        out = []
        deadline = time.time() + timeout
        while len(out) < count and time.time() < deadline:
            while len(self.buf) >= 4 and len(self.buf) >= 4 + int.from_bytes(self.buf[:4], "big") + 2:
                n = 4 + int.from_bytes(self.buf[:4], "big") + 2
                out.append(self.buf[4:n])
                self.buf = self.buf[n:]
            if len(out) >= count:
                break
            self.sock.settimeout(max(0.1, deadline - time.time()))
            try:
                chunk = self.sock.recv(4096)
            except TimeoutError:
                break
            if not chunk:
                break
            self.buf += chunk
        return out

    def close(self):
        self.sock.close()


def rest_apdu(kda, raw):
    """An APDU sent to the emulator's REST endpoint while the signing one waits."""
    c = kda.backend._client
    return bytes.fromhex(c.session.post(f"{c.api_url}/apdu", json={"data": raw.hex()}, timeout=10).json()["data"])


def test_command_during_review_is_refused_and_the_review_signs_unchanged(kda):
    chunks = modern_chunks(0x22, SIMPLE_TRANSFER)
    # The undisturbed review.
    kda.send_all(chunks)
    with kda.pending(chunks[-1]):
        kda.approve_tx()
    sw, clean = kda.result()
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(SIMPLE_TRANSFER), clean[:64])

    kda.send_all(chunks)
    listener = ReplyListener(kda.backend._apdu_port)
    try:
        with kda.pending(chunks[-1]):
            deadline = time.time() + 10
            while "Review transaction" not in kda.texts():
                assert time.time() < deadline, kda.texts()
                time.sleep(0.1)
            assert rest_apdu(kda, apdu(0x20)) == REFUSED
            assert rest_apdu(kda, chunks[0]) == REFUSED
            assert "Review transaction" in kda.texts()
            kda.approve_tx()
        # The emulator handed the signing request one of the refusals.
        assert kda.result() == (0x6901, b"")
        # As the device sent them: the two refusals, then the approved signature.
        sent = listener.replies(3, timeout=15)
    finally:
        listener.close()
    assert sent[:2] == [REFUSED, REFUSED], [r.hex() for r in sent]
    assert len(sent) == 3, [r.hex() for r in sent]
    assert sent[2] == clean + bytes.fromhex("9000")
    # The lock ended with the review: the app answers again.
    deadline = time.time() + 10
    while kda.send(apdu(0x20))[0] != SW_OK:
        assert time.time() < deadline
        time.sleep(0.2)


def test_command_during_address_review_is_refused_and_the_address_is_unchanged(kda):
    """The same lock while an address waits for confirmation (GET_ADDR with P1 = 1):
    a GET_ADDR and a signing command sent meanwhile get 0x6901, the address screen
    does not change, and confirming it returns the key of the requested path."""
    show = apdu(0x21, 1, 0, le(STD))
    listener = ReplyListener(kda.backend._apdu_port)
    try:
        with kda.pending(show):
            deadline = time.time() + 10
            while not any("address" in t.lower() for t in kda.texts()):
                assert time.time() < deadline, kda.texts()
                time.sleep(0.1)
            before = kda.texts()
            assert rest_apdu(kda, apdu(0x21, 0, 0, le(STD))) == REFUSED
            assert rest_apdu(kda, modern_chunks(0x22, SIMPLE_TRANSFER)[0]) == REFUSED
            assert kda.texts() == before
            kda.approve_address()
        # The emulator handed the address request one of the refusals.
        assert kda.result() == (0x6901, b"")
        # As the device sent them: the two refusals, then the confirmed key.
        sent = listener.replies(3, timeout=15)
    finally:
        listener.close()
    assert sent[:2] == [REFUSED, REFUSED], [r.hex() for r in sent]
    assert len(sent) == 3, [r.hex() for r in sent]
    assert sent[2] == bytes.fromhex(EXPECTED_PK) + bytes.fromhex("9000")
    # The lock ended with the review: the app answers again.
    deadline = time.time() + 10
    while kda.send(apdu(0x20))[0] != SW_OK:
        assert time.time() < deadline
        time.sleep(0.2)


def test_malformed_command_during_review_is_refused_like_any_other(kda):
    """SDK 1.42: a malformed APDU (its length byte does not match its data) gets
    the length error when nothing is in flight, but 0x6901 while a review is on
    screen, like any other command then; the review signs unchanged."""
    malformed = bytes.fromhex("0020000005aabb")  # Lc 5, 2 data bytes
    assert kda.send(malformed) == (0x6E03, b"")
    chunks = modern_chunks(0x22, SIMPLE_TRANSFER)
    kda.send_all(chunks)
    listener = ReplyListener(kda.backend._apdu_port)
    try:
        with kda.pending(chunks[-1]):
            deadline = time.time() + 10
            while "Review transaction" not in kda.texts():
                assert time.time() < deadline, kda.texts()
                time.sleep(0.1)
            assert rest_apdu(kda, malformed) == REFUSED
            assert "Review transaction" in kda.texts()
            kda.approve_tx()
        # The emulator handed the signing request the refusal.
        assert kda.result() == (0x6901, b"")
        sent = listener.replies(2, timeout=15)
    finally:
        listener.close()
    assert sent[:1] == [REFUSED], [r.hex() for r in sent]
    assert len(sent) == 2, [r.hex() for r in sent]
    assert sent[1][-2:] == bytes.fromhex("9000")
    verify(EXPECTED_PK, blake2b(SIMPLE_TRANSFER), sent[1][:64])
