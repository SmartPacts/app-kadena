/** ******************************************************************************
 *  (c) 2026 Smart Pacts
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */

// v1.3.1 — a pending signing review locks the app. Which test catches which change:
// - the dispatcher's call to review_lock_allows (apdu_handler.c) removed: THIS test (0x6986 expected);
//   no unit test reaches the dispatcher;
// - review_lock_allows ignoring the pending flag: tests/review_lock.cpp and this test;
// - approval re-hashing the buffer instead of the bound digest (review_lock_digest):
//   tests/review_lock.cpp (ApprovalSignsTheReviewedDigestNotTheBuffer); this test cannot tell, since
//   the lock keeps the buffer unchanged;
// - the digest not bound at parse time (items.c): tests/review_digest.cpp;
// - the approval handlers' own lines (app_sign, legacy_app_sign*): reviewed by reading only.

import Zemu from '@zondax/zemu'
import { KadenaApp } from '@zondax/ledger-kadena'
import Kda from '@zondax/hw-app-kda'
import Transport from '@ledgerhq/hw-transport'
import { getAPDUStatusMessage } from '@zondax/zemu/dist/errors'
import { PATH, defaultOptions, models } from './common'
import { CONTROL_TRANSFER } from './testscases/security'
import { TRANSACTIONS_TEST_CASES } from './testscases/transactions'
import { blake2bFinal, blake2bInit, blake2bUpdate } from 'blakejs'
import { listen } from '@ledgerhq/logs'

// @ts-expect-error
import ed25519 from 'ed25519-supercop'

jest.setTimeout(300000)

function blake(b: Buffer): Buffer {
  const ctx = blake2bInit(32)
  blake2bUpdate(ctx, b)
  return Buffer.from(blake2bFinal(ctx))
}

function decodeHash(encodedHash: string): Buffer {
  let b = encodedHash.replace(/-/g, '+').replace(/_/g, '/')
  while (b.length % 4) b += '='
  return Buffer.from(b, 'base64')
}

function sigBytes(sig: any): Buffer {
  return typeof sig === 'string' ? Buffer.from(sig, 'hex') : Buffer.from(sig)
}

// ---- S12: a pending signing review locks the app ------------------------------------------------
// While a review waits, GET_VERSION is answered (9000), the command's own first APDU is refused with
// a bare 0x6986, the review stays up, and approval signs exactly what an undisturbed review of the
// same transaction signs. The two extra APDUs go to the emulator's REST endpoint while the signing
// APDU is still pending on the transport; the emulator may hand a reply to whichever request is
// waiting, so the three replies are checked as a set.

type Raw = { sw: string; data: string }

async function restApdu(sim: Zemu, apdu: Buffer): Promise<Raw> {
  const s: any = sim
  const r = await fetch(`http://${s.host}:${s.speculosApiPort}/apdu`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ data: apdu.toString('hex') }),
  })
  const hex: string = (await r.json()).data
  return { sw: hex.slice(-4), data: hex.slice(0, -4) }
}

async function rawExchange(t: Transport, apdu: Buffer): Promise<Raw> {
  try {
    const r = await t.exchange(apdu)
    return { sw: r.subarray(-2).toString('hex'), data: r.subarray(0, -2).toString('hex') }
  } catch (e: any) {
    const sw = typeof e?.statusCode === 'number' ? e.statusCode.toString(16).padStart(4, '0') : 'error'
    const bare = typeof e?.statusCode === 'number' && e.message === getAPDUStatusMessage(e.statusCode)
    return { sw, data: bare ? '' : Buffer.from(String(e?.message ?? e)).toString('hex') }
  }
}

// Records every APDU the transport sends (the HTTP transport logs each one as "=> <hex>").
function recordApdus(sent: Buffer[]): () => void {
  return listen((l: any) => {
    if (l.type === 'apdu' && typeof l.message === 'string' && l.message.startsWith('=> ')) {
      sent.push(Buffer.from(l.message.slice(3), 'hex'))
    }
  })
}

type LockCase = { name: string; ins: number; sign: (t: Transport) => Promise<any> }
const S12_TRANSFER = { ...TRANSACTIONS_TEST_CASES.find(c => c.name === 'transfer_1')!.txParams }
const S12_CASES: LockCase[] = [
  { name: '0x22', ins: 0x22, sign: t => new KadenaApp(t).sign(PATH, Buffer.from(CONTROL_TRANSFER, 'utf-8')) },
  { name: '0x03', ins: 0x03, sign: t => new Kda(t).signTransaction(PATH, Buffer.from(CONTROL_TRANSFER, 'utf-8')) },
  { name: '0x24', ins: 0x24, sign: t => new KadenaApp(t).signTransferTx(S12_TRANSFER.path, S12_TRANSFER as any) },
  { name: '0x10', ins: 0x10, sign: t => (new Kda(t) as any)['signTransferTx'](S12_TRANSFER) },
]

describe.each(S12_CASES)('S12 review lock', function (c) {
  test.concurrent.each(models)(`%s locks a pending ${c.name} review and signs what it showed`, async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const t = sim.getTransport()
      // 1. An undisturbed review of the transaction, signed through the host library; its APDUs are
      //    recorded and its reply kept.
      const sent: Buffer[] = []
      await sim.deleteEvents()
      const stop = recordApdus(sent)
      const clean = c.sign(t)
      clean.catch(() => undefined)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.navigateUntilText('.', `tmp-${m.prefix.toLowerCase()}-s12a`, sim.startOptions.approveKeyword, true, false)
      const cleanResult: any = await clean
      stop()
      const signing = sent.filter(a => a[1] === c.ins)
      expect(signing.length).toBeGreaterThan(0)
      const last = signing[signing.length - 1]
      for (const a of signing.slice(0, -1)) {
        expect((await rawExchange(t, a)).sw).toEqual('9000')
      }
      // The clean reply is reproduced by sending the same APDUs again and approving. The event
      // history is cleared first, so the previous review's approve text cannot be taken for this one.
      await sim.deleteEvents()
      const cleanReply = rawExchange(t, last)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.navigateUntilText('.', `tmp-${m.prefix.toLowerCase()}-s12b`, sim.startOptions.approveKeyword, true, false)
      const reference = await cleanReply
      expect(reference.sw).toEqual('9000')

      // 2. The same transaction again; while its review is pending, GET_VERSION and the command's
      //    own first APDU arrive. The device's replies are read from the emulator's log of what the
      //    device sent ("apdu: < <hex>", piped to stdout by Zemu), because the emulator hands a reply
      //    to every request waiting at that moment.
      await sim.deleteEvents()
      for (const a of signing.slice(0, -1)) {
        expect((await rawExchange(t, a)).sw).toEqual('9000')
      }
      const logged: string[] = []
      const write = process.stdout.write.bind(process.stdout)
      ;(process.stdout as any).write = (chunk: any, ...rest: any[]) => {
        logged.push(String(chunk))
        return write(chunk, ...rest)
      }
      let duringReview: string[] = []
      try {
        restApdu(sim, last).catch(() => undefined)
        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
        const mark = logged.length
        restApdu(sim, Buffer.from([0x00, 0x20, 0x00, 0x00, 0x00])).catch(() => undefined)
        await Zemu.sleep(1000)
        restApdu(sim, signing[0]).catch(() => undefined)
        await Zemu.sleep(1500)
        duringReview = logged
          .slice(mark)
          .join('')
          .split('\n')
          .map(l => /apdu: < ([0-9a-f]+)/.exec(l)?.[1])
          .filter((r): r is string => !!r)
        // The review is still on screen: approve it.
        await sim.navigateUntilText('.', `tmp-${m.prefix.toLowerCase()}-s12c`, sim.startOptions.approveKeyword, true, false)
        await Zemu.sleep(1000)
      } finally {
        ;(process.stdout as any).write = write
      }
      // While the review was pending: GET_VERSION answered (12 bytes + 9000), the signing command
      // refused with a bare 0x6986, and nothing else.
      expect(duringReview.length).toEqual(2)
      expect(duringReview[0].slice(-4)).toEqual('9000')
      expect(duringReview[0].length / 2).toEqual(14)
      expect(duringReview[1]).toEqual('6986')

      // 3. Approval ended the review and released the lock: the same transaction, sent afresh, is
      //    accepted chunk by chunk and signs exactly as the undisturbed review did. (The approved
      //    signature of step 2 has no request left to receive it in the emulator; that approval
      //    signs the digest recorded at parse time is proven by tests/review_digest.cpp.)
      await sim.deleteEvents()
      for (const a of signing.slice(0, -1)) {
        expect((await rawExchange(t, a)).sw).toEqual('9000')
      }
      const afterReply = rawExchange(t, last)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.navigateUntilText('.', `tmp-${m.prefix.toLowerCase()}-s12d`, sim.startOptions.approveKeyword, true, false)
      const after = await afterReply
      expect(after).toEqual(reference)
      const sig64 = Buffer.from(after.data, 'hex').subarray(0, 64)
      if (c.ins === 0x22 || c.ins === 0x03) {
        // The reviewed bytes are the JSON sent.
        const json = Buffer.from(CONTROL_TRANSFER, 'utf-8')
        const pk = (await new KadenaApp(t).getAddressAndPubKey(PATH, false)).pubkey
        expect(ed25519.verify(sig64, blake(json), pk)).toEqual(true)
      } else {
        // The reviewed bytes are the template the device built; the host library rebuilt the same
        // command, and its signature (the clean run's) verifies over its hash.
        const cmd = cleanResult.pact_command
        const hash = decodeHash(cmd.hash)
        expect(blake(Buffer.from(cmd.cmd, 'utf-8'))).toEqual(hash)
        expect(sigBytes(cmd.sigs[0].sig)).toEqual(sig64)
      }
    } finally {
      await sim.close()
    }
  })
})
