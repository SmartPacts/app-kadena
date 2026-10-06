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

// v1.3.1 security patch — functional regression for the inherited defects S1-S11 — and, at the end
// of this file, the v1.3.2 rules (streams, one JSON value, blind signing for unbounded signatures,
// screen escaping, amount precision, verifiers, integer gas fields).
// Each refusal asserts the exact status word and, on the commands that carry one (INS 0x22 and
// 0x24), the exact message; the legacy commands (0x03, 0x10) refuse with a bare status word. Where
// a screen changes, the test checks its content. Every case here is refused, or reviewed with a
// warning, by v1.3.1; against the v1.3.0 ELFs each attack reaches a normal review instead.

import Zemu, { ButtonKind, isTouchDevice, TouchNavigation } from '@zondax/zemu'
import { KadenaApp } from '@zondax/ledger-kadena'
import Kda from '@zondax/hw-app-kda'
import Transport from '@ledgerhq/hw-transport'
import { PATH, defaultOptions, models } from './common'
import { getTouchElement } from '@zondax/zemu/dist/buttons'
import { IButton } from '@zondax/zemu/dist/types'
import { getAPDUStatusMessage } from '@zondax/zemu/dist/errors'
import {
  transferBlob,
  TransferFields,
  TRANSFER_OK,
  TRANSFER_FIELD_REJECTS,
  PREFIX_SENDER,
  EMPTY_CLIST,
  DEVICE_SECOND,
  DEVICE_TWICE,
  DEVICE_ABSENT,
  ROTATE,
  TRANSFER_FIELD_EDGE_OK,
  KEY_ATTACKS,
  CONTROL_TRANSFER,
  UNVERIFIED_CAPS,
  DEBIT,
  EXP_AMOUNTS,
  AMOUNT_ACCEPTED,
  AMOUNT_REFUSED,
  TOKEN_NAMESPACE,
  TOKEN_MODULE,
  TOKEN_CAP_JSON,
  DEVICE,
  UNBOUNDED,
  KADENA_CLIENT_1_18_3_COIN_TRANSFER,
  PERMUTED_META_UNKNOWN_KEY,
  longReview,
  longReviewPages,
  exactReview,
  REVIEW_MAX_PAIRS,
  REVIEW_VALUE_CHARS,
  ONE_VALUE_REFUSED,
  TRAILING_WHITESPACE,
  ESCAPED_RECEIVER,
  INVISIBLE_RECEIVER_SHOWN,
  AMOUNT_PRECISION_REFUSED,
  AMOUNT_12_PLACES,
  VERIFIERS,
  NON_INTEGER_META,
} from './testscases/security'
import { TRANSACTIONS_TEST_CASES, HANDLER_LEGACY_TEST_CASES } from './testscases/transactions'
import { JSON_TEST_CASES_V130 } from './testscases/json'
import { APDU_TEST_CASES_V130 } from './testscases/legacy_apdu'
import { NEGATIVE_SIGN_CASES_V130, UNKNOWN_CAP_RENDER_CASE_V130 } from './testscases/negative'

// @ts-expect-error
import ed25519 from 'ed25519-supercop'
import { blake2bFinal, blake2bInit, blake2bUpdate } from 'blakejs'

jest.setTimeout(300000)

const INS_SIGN = 0x22
const INS_SIGN_TRANSFER = 0x24
const INS_LEGACY_TRANSFER = 0x10

// m/44'/626'/0'/0/0 as 5 little-endian u32.
const PATH20 = Buffer.concat(
  [0x8000002c, 0x80000272, 0x80000000, 0, 0].map(c => {
    const b = Buffer.alloc(4)
    b.writeUInt32LE(c >>> 0)
    return b
  }),
)
// qty + qty*u32 LE for m/44'/626'/0'.
const LEGACY_PATH = Buffer.concat([
  Buffer.from([3]),
  ...[0x8000002c, 0x80000272, 0x80000000].map(c => {
    const b = Buffer.alloc(4)
    b.writeUInt32LE(c >>> 0)
    return b
  }),
])

const sw = (r: Buffer) => r.subarray(-2).toString('hex')

// The Zemu transport throws a TransportError whenever the status word is not 0x9000, so normalize
// both outcomes to the 4-hex status word. Every command sent through here must be answered at once:
// a device that goes to a review screen instead (which a refused input never does) is reported as
// 'no reply' after timeoutMs.
async function exchangeSW(t: Transport, apdu: Buffer, timeoutMs = 30000): Promise<string> {
  const reply = t.exchange(apdu).then(
    r => sw(r),
    (e: any) => {
      if (typeof e?.statusCode === 'number') return e.statusCode.toString(16).padStart(4, '0')
      throw e
    },
  )
  let timer: NodeJS.Timeout | undefined
  const timeout = new Promise<string>(resolve => {
    timer = setTimeout(() => resolve('no reply (the device is showing a review)'), timeoutMs)
  })
  try {
    return await Promise.race([reply, timeout])
  } finally {
    clearTimeout(timer)
  }
}

// A reply: the status word and the message bytes before it (empty for a bare status word).
type Reply = { sw: string; msg: string }
const BLIND_REFUSAL: Reply = { sw: '6984', msg: 'Blind signing mode required' }
const PARSE_REFUSAL: Reply = { sw: '6984', msg: 'Unexpected characters' }
const BARE_REFUSAL: Reply = { sw: '6984', msg: '' }
const NOT_A_SIGNER: Reply = { sw: '6984', msg: 'Device key is not a signer' }
const TOO_MANY_TOKENS: Reply = { sw: '6984', msg: 'NOMEM: JSON string contains too many tokens' }
// v1.3.0 fixtures larger than Nano X's 110-token JSON cap (measured on the Nano X emulator).
const NANOX_TOO_MANY_TOKENS: string[] = ['oob_max_items_transfer', 'oob_max_items_rotate']

// Sends one APDU and returns its reply. A device that went to a review instead never answers:
// give up after timeoutMs and report it.
async function reply(t: Transport, apdu: Buffer, timeoutMs = 20000): Promise<Reply> {
  const answer = t.exchange(apdu).then(
    (r: Buffer) => ({ sw: sw(r), msg: r.subarray(0, -2).toString() }),
    (e: any) => {
      if (typeof e?.statusCode !== 'number') return { sw: 'error', msg: String(e?.message ?? e) }
      // The Zemu transport throws on any status but 0x9000, with the reply's bytes as the message,
      // or with getAPDUStatusMessage(sw) when the reply carries no bytes: that is a bare refusal.
      const bare = e.message === getAPDUStatusMessage(e.statusCode)
      return { sw: e.statusCode.toString(16).padStart(4, '0'), msg: bare ? '' : String(e.message) }
    },
  )
  let timer: NodeJS.Timeout | undefined
  const none = new Promise<Reply>(resolve => {
    timer = setTimeout(() => resolve({ sw: 'no reply', msg: 'the device is showing a review' }), timeoutMs)
  })
  try {
    return await Promise.race([answer, none])
  } finally {
    clearTimeout(timer)
  }
}

// INS 0x22: INIT + ADD chunks (each must be acknowledged), then the reply to the LAST chunk.
async function signJsonReply(t: Transport, json: Buffer): Promise<Reply> {
  return reply(t, await sendAllButLast(t, json))
}

// INS 0x24: INIT, then the reply to the LAST APDU carrying the blob.
async function signTransferReply(t: Transport, blob: Buffer): Promise<Reply> {
  expect(await exchangeSW(t, Buffer.concat([Buffer.from([0x00, INS_SIGN_TRANSFER, 0x00, 0x00, PATH20.length]), PATH20]))).toEqual('9000')
  return reply(t, Buffer.concat([Buffer.from([0x00, INS_SIGN_TRANSFER, 0x02, 0x00, blob.length]), blob]))
}

// Legacy INS 0x03 framing (see legacySignJson): the reply to the last slice.
async function legacySignJsonReply(t: Transport, json: Buffer): Promise<Reply> {
  const len = Buffer.alloc(4)
  len.writeUInt32LE(json.length)
  const stream = Buffer.concat([len, json, Buffer.from([5]), PATH20])
  const chunks: Buffer[] = []
  for (let i = 0; i < stream.length; i += 230) chunks.push(stream.subarray(i, Math.min(i + 230, stream.length)))
  for (const c of chunks.slice(0, -1)) {
    const r = await reply(t, Buffer.concat([Buffer.from([0x00, 0x03, 0x00, 0x00, c.length]), c]))
    if (r.sw !== '9000') return r
  }
  const last = chunks[chunks.length - 1]
  return reply(t, Buffer.concat([Buffer.from([0x00, 0x03, 0x00, 0x00, last.length]), last]))
}

// Sends every shape and returns every mismatch, so each shape reports on its own. A shape that
// reaches a review (a failing build) leaves the device waiting for the user, so the emulator is
// restarted before the next shape. Finally the device must still answer GET_VERSION.
type Shape = { label: string; send: (t: Transport) => Promise<Reply>; want: Reply }
async function refuseAll(m: any, shapes: Shape[], blind = false): Promise<string[]> {
  let sim = new Zemu(m.path)
  const failures: string[] = []
  try {
    await sim.start({ ...defaultOptions, model: m.name })
    if (blind) await sim.toggleBlindSigning()
    for (const s of shapes) {
      const got = await s.send(sim.getTransport()).catch((e: any) => ({ sw: 'error', msg: String(e?.message ?? e) }))
      if (got.sw === s.want.sw && got.msg === s.want.msg) continue
      failures.push(`${s.label}: got ${got.sw} "${got.msg}", want ${s.want.sw} "${s.want.msg}"`)
      await sim.close()
      sim = new Zemu(m.path)
      await sim.start({ ...defaultOptions, model: m.name })
      if (blind) await sim.toggleBlindSigning()
    }
    const v = await exchangeSW(sim.getTransport(), Buffer.from([0x00, 0x20, 0x00, 0x00, 0x00]))
    if (v !== '9000') failures.push(`GET_VERSION after the shapes: ${v}`)
  } finally {
    await sim.close()
  }
  return failures
}

// S1: one legacy 0x10 APDU carrying items 1-11 then the ttl length byte only (claims 20
// bytes that were never sent). v1.3.0 signed 20 stale buffer bytes into the undisplayed ttl.
function attackFA(): Buffer {
  const order = [
    'recipient',
    'recipient_chain',
    'network',
    'amount',
    'namespace',
    'module',
    'gas_price',
    'gas_limit',
    'creation_time',
    'chain_id',
    'nonce',
  ] as const
  const parts: Buffer[] = [LEGACY_PATH, Buffer.from([0])]
  for (const k of order) {
    const v = Buffer.from(TRANSFER_OK[k], 'latin1')
    parts.push(Buffer.from([v.length]), v)
  }
  parts.push(Buffer.from([20])) // ttl length byte, no data follows
  const body = Buffer.concat(parts)
  return Buffer.concat([Buffer.from([0x00, INS_LEGACY_TRANSFER, 0x00, 0x00, body.length & 0xff]), body])
}

// F6: a GET_VERSION (0x20) APDU whose data seeds G_io_apdu_buffer[at..at+n) with digit bytes, so
// the S1 attack's undisplayed ttl becomes 20 valid digits. Without the S1 bound v1.3.0 would sign
// those digits (they pass the S3 numeric allowlist); with it the item is refused before any append.
function digitPrimer(at: number, n: number): Buffer {
  const data = Buffer.alloc(at - 5 + n, 0x41)
  for (let i = 0; i < n; i++) data[at - 5 + i] = 0x39 // '9'
  return Buffer.concat([Buffer.from([0x00, 0x20, 0x00, 0x00, data.length & 0xff]), data])
}

// S2: APDU1 (rx=210) ends with the module length byte at offset 205 claiming 32 bytes, so
// the item straddles the 235-byte boundary while rx < 235. v1.3.0 copied 25 stale bytes and
// replied 0x9000; v1.3.1 refuses APDU1 with 0x6700.
function attackFB(): Buffer {
  const f = {
    ...TRANSFER_OK,
    recipient: 'a'.repeat(64),
    recipient_chain: '00',
    network: 'n'.repeat(20),
    amount: '1'.repeat(32),
    namespace: 'n'.repeat(63),
  }
  const order = ['recipient', 'recipient_chain', 'network', 'amount', 'namespace'] as const
  const parts: Buffer[] = [LEGACY_PATH, Buffer.from([0])]
  for (const k of order) {
    const v = Buffer.from(f[k], 'latin1')
    parts.push(Buffer.from([v.length]), v)
  }
  parts.push(Buffer.from([32])) // module length byte at offset 205, no module data in this APDU
  const body = Buffer.concat(parts)
  const apdu = Buffer.concat([Buffer.from([0x00, INS_LEGACY_TRANSFER, 0x00, 0x00, body.length & 0xff]), body])
  expect(apdu.length).toEqual(206) // module length byte at offset 205, rx = 206 (< 235)
  return apdu
}

// Signs a JSON over INS 0x22, walks the review to the approve step and approves, collecting every
// screen's text so the test can assert on the review content (model-independent).
async function reviewAndApprove(sim: Zemu, m: any, json: Buffer, blind = false): Promise<{ seen: string; signature: Promise<Buffer> }> {
  const app = new KadenaApp(sim.getTransport())
  const signature = app.sign(PATH, json).then((r: any) => r.signature as Buffer)
  signature.catch(() => undefined)
  await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
  // Walk to the approve step and approve, collecting every screen's text (no snapshot compare: the
  // content assertions below are on the text, which is model-independent).
  await sim.navigateUntilText(
    '.',
    `tmp-${m.prefix.toLowerCase()}`,
    sim.startOptions.approveKeyword,
    true,
    false,
    0,
    30000,
    true,
    true,
    blind,
  )
  const seen = (await sim.getEvents()).map((e: any) => e.text).join(' | ')
  return { seen, signature }
}

// Every screen text seen so far, with page headers ("WARNING (1/2)") and separators removed, so a
// paginated value reads as one string.
async function seenCollapsed(sim: Zemu): Promise<string> {
  const text = (await sim.getEvents()).map((e: any) => e.text).join(' | ')
  return text.replace(/[A-Za-z ]+\(\d+\/\d+\)/g, '').replace(/[\s|]+/g, '')
}

function blake(json: Buffer): Buffer {
  const ctx = blake2bInit(32)
  blake2bUpdate(ctx, json)
  return Buffer.from(blake2bFinal(ctx))
}

// Legacy INS 0x03: payload_len (u32 LE) + JSON + path qty + path, sent in 230-byte slices the way
// hw-app-kda frames it. Returns the status word of the last APDU.
async function legacySignJson(t: Transport, json: Buffer, path: string): Promise<string> {
  const comps = path
    .replace(/^m\//, '')
    .split('/')
    .map(c => (c.endsWith("'") ? (0x80000000 | parseInt(c)) >>> 0 : parseInt(c)))
  const len = Buffer.alloc(4)
  len.writeUInt32LE(json.length)
  const stream = Buffer.concat([
    len,
    json,
    Buffer.from([comps.length]),
    ...comps.map(c => {
      const b = Buffer.alloc(4)
      b.writeUInt32LE(c)
      return b
    }),
  ])
  let last = ''
  for (let i = 0; i < stream.length; i += 230) {
    const chunk = stream.subarray(i, Math.min(i + 230, stream.length))
    last = await exchangeSW(t, Buffer.concat([Buffer.from([0x00, 0x03, 0x00, 0x00, chunk.length]), chunk]))
    if (last !== '9000') break
  }
  return last
}

describe('S1: legacy 0x10 final item OOB into the undisplayed ttl', function () {
  test.concurrent.each(models)('%s refuses 0x6700', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const t = sim.getTransport()
      // Seed the stale ttl region with digits (F6), so the attack exercises S1 and not the S3
      // numeric allowlist: v1.3.0 would sign those digits, v1.3.1 refuses the over-long item.
      const attack = attackFA()
      expect(await exchangeSW(t, digitPrimer(attack.length, 20))).toEqual('9000')
      expect(await exchangeSW(t, attack)).toEqual('6700')
      // The app survives.
      expect(await exchangeSW(t, Buffer.from([0x00, 0x20, 0x00, 0x00, 0x00]))).toEqual('9000')
    } finally {
      await sim.close()
    }
  })
})

describe('S2: legacy split reads past the received length', function () {
  test.concurrent.each(models)('%s refuses 0x6700 on the short chunk', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      expect(await exchangeSW(sim.getTransport(), attackFB())).toEqual('6700')
      expect(await exchangeSW(sim.getTransport(), Buffer.from([0x00, 0x20, 0x00, 0x00, 0x00]))).toEqual('9000')
    } finally {
      await sim.close()
    }
  })
})

describe('S3 injection: structured-transfer field content allowlist', function () {
  test.concurrent.each(models)(
    '%s refuses every out-of-grammar field with 0x6984',
    async function (m) {
      const shapes: Shape[] = [
        // 0x24: "Unexpected characters" + 0x6984.
        ...TRANSFER_FIELD_REJECTS.map(c => ({
          label: `${c.name} 0x24`,
          send: (t: Transport) => signTransferReply(t, transferBlob({ ...TRANSFER_OK, ...c.fields } as TransferFields, c.txType ?? 0)),
          want: PARSE_REFUSAL,
        })),
        // Legacy 0x10 carries the same fields: refused with a bare 0x6984.
        ...TRANSFER_FIELD_REJECTS.slice(0, 4).map(c => ({
          label: `${c.name} 0x10`,
          send: (t: Transport) => {
            const body = Buffer.concat([LEGACY_PATH, transferBlob({ ...TRANSFER_OK, ...c.fields }, c.txType ?? 0)])
            return reply(t, Buffer.concat([Buffer.from([0x00, INS_LEGACY_TRANSFER, 0x00, 0x00, body.length]), body]))
          },
          want: BARE_REFUSAL,
        })),
      ]
      expect(await refuseAll(m, shapes)).toEqual([])
    },
    1200000,
  )

  // F5: a positive test for the allowlist's grammar edges (exponent gas price, long decimal amount,
  // punctuation nonce, network with -_. , gas limit 0). The device builds the same template the
  // host library does, so the device signature verifies against the host-built hash.
  test.concurrent.each(models)('%s signs the allowlist grammar edges', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new KadenaApp(sim.getTransport())
      const req = app.signTransferTx(PATH, {
        path: PATH,
        recipient: TRANSFER_FIELD_EDGE_OK.recipient,
        recipient_chainId: 0,
        network: TRANSFER_FIELD_EDGE_OK.network,
        amount: TRANSFER_FIELD_EDGE_OK.amount,
        chainId: 0,
        gasPrice: TRANSFER_FIELD_EDGE_OK.gas_price,
        gasLimit: TRANSFER_FIELD_EDGE_OK.gas_limit,
        creationTime: 0,
        ttl: TRANSFER_FIELD_EDGE_OK.ttl,
        nonce: TRANSFER_FIELD_EDGE_OK.nonce,
      } as any)
      const catcher = req.catch(() => undefined)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.navigateUntilText('.', `tmp-${m.prefix.toLowerCase()}-s3edge`, sim.startOptions.approveKeyword, true, false)
      // S13: a plain coin transfer carries no "Capability not verified" warning.
      expect(await seenCollapsed(sim)).not.toMatch(/notverified/)
      const res: any = await catcher
      expect(res).toBeDefined()
      const hash = decodeHash(res.pact_command.hash)
      const pk = (await new KadenaApp(sim.getTransport()).getAddressAndPubKey(PATH, false)).pubkey
      expect(ed25519.verify(Buffer.from(res.pact_command.sigs[0].sig, 'hex'), hash, pk)).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

function decodeHash(encodedHash: string): Buffer {
  let b = encodedHash.replace(/-/g, '+').replace(/_/g, '/')
  while (b.length % 4) b += '='
  return Buffer.from(b, 'base64')
}

describe('S4 prefix match: a sender that only starts with the device key is not the signer', function () {
  test.concurrent.each(models)('%s shows Unscoped Signer', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const json = Buffer.from(PREFIX_SENDER, 'utf-8')
      const { seen, signature } = await reviewAndApprove(sim, m, json)
      expect(seen).toMatch(/Unscoped Signer/)
      const pk = (await new KadenaApp(sim.getTransport()).getAddressAndPubKey(PATH, false)).pubkey
      expect(ed25519.verify(await signature, blake(json), pk)).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

describe('S5 empty clist is unscoped', function () {
  // Since v1.3.2 an unscoped signature is blind signing: reviewed with the setting on (refused with it
  // off, see the v1.3.2 rule 3 tests).
  test.concurrent.each(models)('%s shows Unscoped Signer and the WARNING', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      await sim.toggleBlindSigning()
      const json = Buffer.from(EMPTY_CLIST, 'utf-8')
      const { seen, signature } = await reviewAndApprove(sim, m, json, true)
      expect(seen).toMatch(/Unscoped Signer/)
      // The WARNING text is paginated on Nano; collapse spaces and page separators.
      expect(seen.replace(/[\s|]+/g, '')).toMatch(/UNSAFETRANSACTION/)
      const pk = (await new KadenaApp(sim.getTransport()).getAddressAndPubKey(PATH, false)).pubkey
      expect(ed25519.verify(await signature, blake(json), pk)).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

describe('S6 the device signer entry, not signers[0]', function () {
  test.concurrent.each(models)('%s refuses 0x6984 when the device key is absent or repeated', async function (m) {
    const shapes: Shape[] = [
      { label: 'device absent 0x22', send: t => signJsonReply(t, Buffer.from(DEVICE_ABSENT, 'utf-8')), want: NOT_A_SIGNER },
      {
        label: 'device twice 0x22',
        send: t => signJsonReply(t, Buffer.from(DEVICE_TWICE, 'utf-8')),
        want: { sw: '6984', msg: 'Device key signs more than once' },
      },
      { label: 'device absent 0x03', send: t => legacySignJsonReply(t, Buffer.from(DEVICE_ABSENT, 'utf-8')), want: BARE_REFUSAL },
      { label: 'device twice 0x03', send: t => legacySignJsonReply(t, Buffer.from(DEVICE_TWICE, 'utf-8')), want: BARE_REFUSAL },
    ]
    expect(await refuseAll(m, shapes)).toEqual([])
  })

  test.concurrent.each(models)(
    '%s refuses the v1.3.0 fixtures whose signer is not the device key',
    async function (m) {
      const shapes: Shape[] = [
        // Modern 0x22: "Device key is not a signer" + 0x6984. On Nano X (a 110-token JSON cap, see
        // json_parser.h) the larger fixtures are refused for their size before the signer check.
        // The NEGATIVE_SIGN_CASES (F15 memory-safety inputs) were already refused by v1.3.0; they
        // pin that v1.3.1 refuses them too, now at the signer check.
        ...[...JSON_TEST_CASES_V130, UNKNOWN_CAP_RENDER_CASE_V130, ...NEGATIVE_SIGN_CASES_V130].map(c => ({
          label: `${c.name} 0x22`,
          send: (t: Transport) => signJsonReply(t, Buffer.from(c.json, 'utf-8')),
          want: m.name === 'nanox' && NANOX_TOO_MANY_TOKENS.includes(c.name) ? TOO_MANY_TOKENS : NOT_A_SIGNER,
        })),
        // Legacy 0x03: bare 0x6984.
        ...[...JSON_TEST_CASES_V130, ...APDU_TEST_CASES_V130].map(c => ({
          label: `${c.name} 0x03`,
          send: async (t: Transport) => ({ sw: await legacySignJson(t, Buffer.from(c.json, 'utf-8'), c.path), msg: '' }),
          want: BARE_REFUSAL,
        })),
      ]
      expect(await refuseAll(m, shapes)).toEqual([])
    },
    1200000,
  )

  test.concurrent.each(models)('%s reviews the device entry when it is not signers[0]', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const json = Buffer.from(DEVICE_SECOND, 'utf-8')
      const { seen, signature } = await reviewAndApprove(sim, m, json)
      expect(seen).toMatch(/Signers/)
      expect(seen).toMatch(/Normal Transfer/)
      expect(seen).not.toMatch(/Unscoped Signer/)
      const pk = (await new KadenaApp(sim.getTransport()).getAddressAndPubKey(PATH, false)).pubkey
      expect(ed25519.verify(await signature, blake(json), pk)).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

describe('S7 coin.ROTATE needs the Blind signing setting', function () {
  test.concurrent.each(models)('%s refuses with Blind signing off', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      // The blind-signing screen, then "Blind signing mode required" + 0x6984.
      const last = await sendAllButLast(sim.getTransport(), Buffer.from(ROTATE, 'utf-8'))
      expect(await lastReply(sim, m, last, true)).toEqual(BLIND_REFUSAL)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('%s reviews with the rotation warning when Blind signing is on', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      await sim.toggleBlindSigning()
      const json = Buffer.from(ROTATE, 'utf-8')
      const { seen, signature } = await reviewAndApprove(sim, m, json, true)
      expect(seen).toMatch(/Rotate for account/)
      expect(seen.replace(/[\s|]+/g, '')).toMatch(/Accountrotation:newownernotshown/)
      const pk = (await new KadenaApp(sim.getTransport()).getAddressAndPubKey(PATH, false)).pubkey
      expect(ed25519.verify(await signature, blake(json), pk)).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

// A legacy 0x03 signing that must reach the review and sign: every chunk but the last is
// acknowledged, the last one blocks on the review, and the reply is sig(64) + 9000.
async function legacySignJsonApproved(sim: Zemu, json: Buffer): Promise<Buffer> {
  const t = sim.getTransport()
  // Start from an empty event history, so an earlier review's approve text cannot be mistaken for
  // this review's approve step.
  await sim.deleteEvents()
  const len = Buffer.alloc(4)
  len.writeUInt32LE(json.length)
  const path = Buffer.concat([Buffer.from([5]), PATH20])
  const stream = Buffer.concat([len, json, path])
  const chunks: Buffer[] = []
  for (let i = 0; i < stream.length; i += 230) chunks.push(stream.subarray(i, Math.min(i + 230, stream.length)))
  for (const c of chunks.slice(0, -1)) {
    expect(await exchangeSW(t, Buffer.concat([Buffer.from([0x00, 0x03, 0x00, 0x00, c.length]), c]))).toEqual('9000')
  }
  const last = chunks[chunks.length - 1]
  const reply = t.exchange(Buffer.concat([Buffer.from([0x00, 0x03, 0x00, 0x00, last.length]), last]))
  reply.catch(() => undefined)
  await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
  await sim.navigateUntilText('.', 'tmp-legacy03', sim.startOptions.approveKeyword, true, false)
  const r = await reply
  expect(r.subarray(-2).toString('hex')).toEqual('9000')
  return r.subarray(0, 64)
}

describe('S8/S9 escaped and duplicate JSON keys', function () {
  test.concurrent.each(models)(
    '%s refuses every escaped or duplicate key (0x22 and legacy 0x03)',
    async function (m) {
      const shapes: Shape[] = KEY_ATTACKS.flatMap(a => [
        {
          label: `${a.name} 0x22`,
          send: (t: Transport) => signJsonReply(t, Buffer.from(a.json, 'utf-8')),
          want: { sw: '6984', msg: a.msg },
        },
        { label: `${a.name} 0x03`, send: (t: Transport) => legacySignJsonReply(t, Buffer.from(a.json, 'utf-8')), want: BARE_REFUSAL },
      ])
      expect(await refuseAll(m, shapes)).toEqual([])
    },
    1200000,
  )

  // Controls: a clean transfer with the device key still reaches the review and signs over 0x22
  // AND over legacy 0x03, so the 0x03 refusals above are not an artefact of the 0x03 framing.
  test.concurrent.each(models)('%s still signs a clean transfer over 0x22 and 0x03', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const pk = (await new KadenaApp(sim.getTransport()).getAddressAndPubKey(PATH, false)).pubkey
      const control = Buffer.from(CONTROL_TRANSFER, 'utf-8')
      const { signature } = await reviewAndApprove(sim, m, control)
      expect(ed25519.verify(await signature, blake(control), pk)).toEqual(true)
      const sig03 = await legacySignJsonApproved(sim, control)
      expect(ed25519.verify(sig03, blake(control), pk)).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})
// Dismisses the blind-signing refusal screen. The refusal's reply (0x6984) can arrive while Zemu is
// still waiting for the screen to repaint, and Zemu then aborts that wait with a 0x6984 transport
// error; that reply is the one the caller asserts, so only that error is tolerated here.
async function dismissBlindRefusal(sim: Zemu, m: any): Promise<void> {
  try {
    if (isTouchDevice(m.name)) {
      // "This transaction cannot be clear-signed" -> Reject Transaction.
      await sim.fingerTouch(getTouchElement(m.name, ButtonKind.RejectButton) as IButton)
    } else {
      // Nano: "Blind signing must be / enabled in Settings" -> dismiss.
      await sim.waitForText('Blind signing must be')
      await sim.clickBoth()
    }
  } catch (e: any) {
    if (e?.statusCode !== 0x6984) throw e
  }
}

// Sends the final APDU of a signing and returns its status word and message. A refusal the device
// decides at parse time answers at once; a Blind-signing refusal first shows the blind-signing
// screen and answers only once the user dismisses it, so `dismissBlind` walks that screen.
async function lastReply(sim: Zemu, m: any, apdu: Buffer, dismissBlind: boolean): Promise<Reply> {
  const answer = reply(sim.getTransport(), apdu, dismissBlind ? 60000 : 20000)
  if (dismissBlind) {
    await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
    await dismissBlindRefusal(sim, m)
  }
  return answer
}

// Legacy INS 0x03 (see legacySignJson): every slice but the last, each acknowledged, and the last
// slice returned for lastReply.
async function legacySendAllButLast(t: Transport, json: Buffer): Promise<Buffer> {
  const len = Buffer.alloc(4)
  len.writeUInt32LE(json.length)
  const stream = Buffer.concat([len, json, Buffer.from([5]), PATH20])
  const chunks: Buffer[] = []
  for (let i = 0; i < stream.length; i += 230) chunks.push(stream.subarray(i, Math.min(i + 230, stream.length)))
  for (const c of chunks.slice(0, -1)) {
    expect(await exchangeSW(t, Buffer.concat([Buffer.from([0x00, 0x03, 0x00, 0x00, c.length]), c]))).toEqual('9000')
  }
  const last = chunks[chunks.length - 1]
  return Buffer.concat([Buffer.from([0x00, 0x03, 0x00, 0x00, last.length]), last])
}

// INS 0x22: INIT + ADD chunks, and the LAST chunk returned for lastReply.
async function sendAllButLast(t: Transport, json: Buffer): Promise<Buffer> {
  expect(await exchangeSW(t, Buffer.concat([Buffer.from([0x00, INS_SIGN, 0x00, 0x00, PATH20.length]), PATH20]))).toEqual('9000')
  const chunks: Buffer[] = []
  for (let i = 0; i < json.length; i += 250) chunks.push(json.subarray(i, Math.min(i + 250, json.length)))
  for (let i = 0; i < chunks.length - 1; i++) {
    expect(await exchangeSW(t, Buffer.concat([Buffer.from([0x00, INS_SIGN, 0x01, 0x00, chunks[i].length]), chunks[i]]))).toEqual('9000')
  }
  const last = chunks[chunks.length - 1]
  return Buffer.concat([Buffer.from([0x00, INS_SIGN, 0x02, 0x00, last.length]), last])
}

// Each S10/S11 shape is its own test on a fresh emulator, so every shape reports on its own. Shapes
// go over 0x22 unless `legacy` is set (legacy 0x03). An exponent in the 0x24 / 0x10 amount field is an
// S3 case (the allowlist admits only plain decimals there), so it is in TRANSFER_FIELD_REJECTS.
const S10_S11_SHAPES: { name: string; json: string; blind: boolean; legacy?: boolean }[] = [
  ...UNVERIFIED_CAPS.map(c => ({ name: c.name, json: c.json, blind: true })),
  // A token module's TRANSFER in host-built JSON (0x22) is not fully reviewed.
  { name: 's10_token_cap_0x22', json: TOKEN_CAP_JSON, blind: true },
  ...EXP_AMOUNTS.map(c => ({ name: c.name, json: c.json, blind: false })),
  // Legacy 0x03: the blind refusal carries its message; a parse refusal is a bare 0x6984.
  { name: 's10_debit_0x03', json: UNVERIFIED_CAPS[0].json, blind: true, legacy: true },
  { name: 's11_number_0x03', json: EXP_AMOUNTS[0].json, blind: false, legacy: true },
]

describe.each(S10_S11_SHAPES)('S10/S11/S14 refusal with Blind signing off', function (c) {
  test.concurrent.each(models)(`%s refuses ${c.name}`, async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const t = sim.getTransport()
      const json = Buffer.from(c.json, 'utf-8')
      const last = c.legacy ? await legacySendAllButLast(t, json) : await sendAllButLast(t, json)
      // S10 shapes show the blind-signing screen, then refuse; S11 shapes are refused at parse time.
      const parseRefusal = c.legacy ? BARE_REFUSAL : PARSE_REFUSAL
      expect(await lastReply(sim, m, last, c.blind)).toEqual(c.blind ? BLIND_REFUSAL : parseRefusal)
      // The device survives.
      expect(await exchangeSW(t, Buffer.from([0x00, 0x20, 0x00, 0x00, 0x00]))).toEqual('9000')
    } finally {
      await sim.close()
    }
  })
})

describe('S10/S11 controls and the Blind-signing review', function () {
  // S13: a structured transfer of a token other than coin needs Blind signing. With it off it is
  // refused: after the blind-signing screen over 0x24, with a bare 0x6984 over legacy 0x10.
  test.concurrent.each(models)('%s refuses a token transfer with Blind signing off (0x24, 0x10)', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const t = sim.getTransport()
      const token = transferBlob({ ...TRANSFER_OK, namespace: TOKEN_NAMESPACE, module: TOKEN_MODULE }, 0)
      expect(await exchangeSW(t, Buffer.concat([Buffer.from([0x00, INS_SIGN_TRANSFER, 0x00, 0x00, PATH20.length]), PATH20]))).toEqual(
        '9000',
      )
      const last = Buffer.concat([Buffer.from([0x00, INS_SIGN_TRANSFER, 0x02, 0x00, token.length]), token])
      expect(await lastReply(sim, m, last, true)).toEqual(BLIND_REFUSAL)
      const body = Buffer.concat([LEGACY_PATH, token])
      expect(await reply(t, Buffer.concat([Buffer.from([0x00, INS_LEGACY_TRANSFER, 0x00, 0x00, body.length]), body]))).toEqual(BARE_REFUSAL)
      expect(await exchangeSW(t, Buffer.from([0x00, 0x20, 0x00, 0x00, 0x00]))).toEqual('9000')
    } finally {
      await sim.close()
    }
  })

  // S13: with Blind signing on, the token transfer is reviewed with the warning naming the token's
  // TRANSFER, and the signature verifies over the transaction the device built.
  test.concurrent.each(models)('%s reviews a token transfer with the warning when Blind signing is on', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      await sim.toggleBlindSigning()
      const app = new KadenaApp(sim.getTransport())
      const pk = (await app.getAddressAndPubKey(PATH, false)).pubkey
      const token = TRANSACTIONS_TEST_CASES.find(c => c.name === 'transfer_namespace_42')!
      const req = app.signTransferTx(PATH, token.txParams as any)
      const catcher = req.catch((e: any) => e)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.navigateUntilText(
        '.',
        `tmp-${m.prefix.toLowerCase()}-token`,
        sim.startOptions.approveKeyword,
        true,
        false,
        0,
        30000,
        true,
        true,
        true,
      )
      expect(await seenCollapsed(sim)).toMatch(/Capabilitynotverified:n_e595727b657fbbb3b8e362a05a7bb8d12865c1ff\.kb-USDC\.TRANSFER/)
      const res: any = await catcher
      expect(res?.pact_command?.cmd).toContain('kb-USDC.TRANSFER')
      const hash = decodeHash(res.pact_command.hash)
      expect(blake(Buffer.from(res.pact_command.cmd, 'utf-8'))).toEqual(hash)
      expect(ed25519.verify(Buffer.from(res.pact_command.sigs[0].sig, 'hex'), hash, pk)).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('%s still clear-signs a plain transfer', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const pk = (await new KadenaApp(sim.getTransport()).getAddressAndPubKey(PATH, false)).pubkey
      const control = Buffer.from(CONTROL_TRANSFER, 'utf-8')
      const r = await reviewAndApprove(sim, m, control)
      expect(r.seen).not.toMatch(/not verified/)
      expect(ed25519.verify(await r.signature, blake(control), pk)).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('%s reviews coin.DEBIT with the warning when Blind signing is on', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      await sim.toggleBlindSigning()
      const json = Buffer.from(DEBIT, 'utf-8')
      const { seen, signature } = await reviewAndApprove(sim, m, json, true)
      expect(seen.replace(/[\s|]+/g, '')).toMatch(/Capabilitynotverified:coin\.DEBIT/)
      const pk = (await new KadenaApp(sim.getTransport()).getAddressAndPubKey(PATH, false)).pubkey
      expect(ed25519.verify(await signature, blake(json), pk)).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

describe('S14 transfer amounts (bare number or decimal object)', function () {
  // The two accepted forms are reviewed with the plain number and sign, over 0x22 and legacy 0x03.
  test.concurrent.each(models)(
    '%s reviews and signs each accepted amount form, shown as a plain number',
    async function (m) {
      const sim = new Zemu(m.path)
      try {
        await sim.start({ ...defaultOptions, model: m.name })
        const pk = (await new KadenaApp(sim.getTransport()).getAddressAndPubKey(PATH, false)).pubkey
        for (const c of AMOUNT_ACCEPTED) {
          const json = Buffer.from(c.json, 'utf-8')
          await sim.deleteEvents()
          const r = await reviewAndApprove(sim, m, json)
          // The amount value is one screen element; it must read exactly "KDA 231" (not, say,
          // "KDA 2310"), and the object text never appears.
          const lines = r.seen.split(' | ')
          expect([c.name, '0x22', lines.includes(c.shown), r.seen.includes('decimal')]).toEqual([c.name, '0x22', true, false])
          expect(ed25519.verify(await r.signature, blake(json), pk)).toEqual(true)
          const sig03 = await legacySignJsonApproved(sim, json)
          const lines03 = (await sim.getEvents()).map((e: any) => e.text)
          expect([c.name, '0x03', lines03.includes(c.shown), lines03.join(' ').includes('decimal')]).toEqual([c.name, '0x03', true, false])
          expect(ed25519.verify(sig03, blake(json), pk)).toEqual(true)
        }
      } finally {
        await sim.close()
      }
    },
    1200000,
  )

  // Every other form is refused before any screen: "Unexpected characters" over 0x22, bare over 0x03.
  test.concurrent.each(models)(
    '%s refuses every other amount form (0x22 and legacy 0x03)',
    async function (m) {
      const shapes: Shape[] = AMOUNT_REFUSED.flatMap(c => [
        { label: `${c.name} 0x22`, send: (t: Transport) => signJsonReply(t, Buffer.from(c.json, 'utf-8')), want: PARSE_REFUSAL },
        { label: `${c.name} 0x03`, send: (t: Transport) => legacySignJsonReply(t, Buffer.from(c.json, 'utf-8')), want: BARE_REFUSAL },
      ])
      expect(await refuseAll(m, shapes)).toEqual([])
    },
    1200000,
  )
})

// ================================================================================================
// v1.3.2. Every refusal below asserts the exact status word and, over 0x22 / 0x24, the exact message;
// against the v1.3.1 ELFs each one reaches a review or is accepted instead. Each rule also has a
// positive case that still signs.
// ================================================================================================

const INS_SIGN_HASH = 0x23
const apdu = (ins: number, p1: number, data: Buffer) => Buffer.concat([Buffer.from([0x00, ins, p1, 0x00, data.length]), data])
const GET_VERSION = Buffer.from([0x00, 0x20, 0x00, 0x00, 0x00])

// A 230-byte first chunk of a legacy 0x03 stream: length 1000 (never reached), then 226 spaces.
const FIRST_03 = apdu(0x03, 0, Buffer.concat([Buffer.from([0xe8, 0x03, 0x00, 0x00]), Buffer.alloc(226, 0x20)]))

// The 230-byte slices of a legacy stream, as the host frames them.
function legacySlices(ins: number, stream: Buffer): Buffer[] {
  const out: Buffer[] = []
  for (let i = 0; i < stream.length; i += 230) out.push(apdu(ins, 0, stream.subarray(i, Math.min(i + 230, stream.length))))
  return out
}
const legacyJsonSlices = (json: Buffer) => {
  const len = Buffer.alloc(4)
  len.writeUInt32LE(json.length)
  return legacySlices(0x03, Buffer.concat([len, json, Buffer.from([5]), PATH20]))
}

// m/44'/626'/5'/0/0: another key, for the address commands sent between chunks.
const ALT_COMPONENTS = [0x8000002c, 0x80000272, 0x80000005, 0, 0]
const ALT_PATH20 = Buffer.concat(
  ALT_COMPONENTS.map(c => {
    const b = Buffer.alloc(4)
    b.writeUInt32LE(c >>> 0)
    return b
  }),
)
const LEGACY_GET_PUBKEY_ALT = apdu(0x02, 0, Buffer.concat([Buffer.from([5]), ALT_PATH20]))
const GET_ADDR_ALT = apdu(0x21, 0, ALT_PATH20)

// The 287-byte token transfer of the legacy handler tests: two legacy 0x10 APDUs.
function longLegacyTransfer(): Buffer[] {
  const p = HANDLER_LEGACY_TEST_CASES.find(c => c.name === 'handler_legacy_len_287')!.txParams
  const blob = transferBlob(
    {
      recipient: p.recipient,
      recipient_chain: String(p.recipient_chainId),
      network: p.network,
      amount: p.amount,
      namespace: p.namespace,
      module: p.module,
      gas_price: p.gasPrice,
      gas_limit: p.gasLimit,
      creation_time: String(p.creationTime),
      chain_id: String(p.chainId),
      nonce: p.nonce,
      ttl: p.ttl,
    },
    0,
  )
  const slices = legacySlices(INS_LEGACY_TRANSFER, Buffer.concat([Buffer.from([5]), PATH20, blob]))
  expect(slices.length).toEqual(2)
  return slices
}

// Sends `apdus` in order; every one but the last must be acknowledged with 0x9000. Returns the reply
// to the last one (or the first one that was not acknowledged).
async function sendAll(t: Transport, apdus: Buffer[]): Promise<Reply> {
  for (const a of apdus.slice(0, -1)) {
    const r = await reply(t, a)
    if (r.sw !== '9000') return { sw: `${r.sw} (early)`, msg: r.msg }
  }
  return reply(t, apdus[apdus.length - 1])
}

// Several replies as one: the status words joined with '/', the messages concatenated.
function joined(rs: Reply[]): Reply {
  return { sw: rs.map(r => r.sw).join('/'), msg: rs.map(r => r.msg).join('') }
}

// Returns sim's transport, set to send `extra` (an address command for another path) right after the
// first APDU with INS `ins` is answered, recording its reply. The host libraries call `send`, which is
// bound to the emulator's underlying transport, so that transport's own `exchange` is wrapped (once).
function injectAfterFirst(sim: Zemu, ins: number, extra: Buffer, seen: Reply[]): Transport {
  const raw: any = (sim as any).transport
  const exchange = raw.exchange.bind(raw)
  raw.exchange = async (a: Buffer) => {
    const r = await exchange(a)
    if (a[1] === ins) {
      delete raw.exchange
      seen.push(await reply(sim.getTransport(), extra))
    }
    return r
  }
  return sim.getTransport()
}

describe('v1.3.2 rule 1: one signing stream, bound to its command and its path', function () {
  test.concurrent.each(models)(
    '%s refuses a chunk of another command while a stream is open (0x6987) and closes the stream',
    async function (m) {
      const json = Buffer.from(CONTROL_TRANSFER, 'utf-8')
      const slices03 = legacyJsonSlices(json)
      expect(slices03.length).toEqual(4)
      const hashPayload = Buffer.concat([Buffer.alloc(32, 0x5a), Buffer.from([5]), PATH20])
      const coinTransfer = apdu(INS_LEGACY_TRANSFER, 0, Buffer.concat([LEGACY_PATH, transferBlob(TRANSFER_OK, 0)]))
      const shapes: Shape[] = []
      // Every pair of modern signing commands: the second INS is refused, and so is the first one's
      // next chunk (the stream is closed). With Blind signing on, a JSON stream finished as 0x23 was
      // reviewed as a hash by v1.3.1.
      for (const first of [INS_SIGN, INS_SIGN_HASH, INS_SIGN_TRANSFER]) {
        for (const second of [INS_SIGN, INS_SIGN_HASH, INS_SIGN_TRANSFER]) {
          if (first === second) continue
          for (const p1 of [1, 2]) {
            shapes.push({
              label: `0x${first.toString(16)} then 0x${second.toString(16)} P1=${p1}`,
              send: async t => {
                const init = await reply(t, apdu(first, 0, PATH20))
                if (init.sw !== '9000') return init
                return joined([await reply(t, apdu(second, p1, Buffer.alloc(32, 7))), await reply(t, apdu(first, 2, Buffer.alloc(32, 7)))])
              },
              want: { sw: '6987/6987', msg: '' },
            })
          }
        }
      }
      shapes.push(
        {
          label: '0x22 INIT + ADD, finished with 0x23',
          send: async t =>
            sendAll(t, [
              apdu(INS_SIGN, 0, PATH20),
              apdu(INS_SIGN, 1, Buffer.alloc(16, 0x5a)),
              apdu(INS_SIGN_HASH, 2, Buffer.alloc(16, 0x5a)),
            ]),
          want: { sw: '6987', msg: '' },
        },
        {
          label: 'legacy 0x03 chunk during a 0x22 stream',
          send: async t => {
            const init = await reply(t, apdu(INS_SIGN, 0, PATH20))
            if (init.sw !== '9000') return init
            return joined([await reply(t, FIRST_03), await reply(t, apdu(INS_SIGN, 1, Buffer.from('{}')))])
          },
          want: { sw: '6987/6987', msg: '' },
        },
        {
          label: 'a 0x22 first chunk closes an open 0x03 stream',
          send: async t => sendAll(t, [slices03[0], apdu(INS_SIGN, 0, PATH20), slices03[1]]),
          want: { sw: '6987', msg: '' },
        },
        {
          // The 0x22 chunk closes the 0x03 stream, so the rest of the 0x03 data is read as a new
          // command whose first 4 bytes (JSON text) are a length it never reaches: refused.
          label: 'a 0x22 chunk during a 0x03 stream is refused and closes it',
          send: async t => {
            const first = await reply(t, slices03[0])
            if (first.sw !== '9000') return first
            const refused = await reply(t, apdu(INS_SIGN, 1, Buffer.from('xx')))
            return joined([refused, await sendAll(t, slices03.slice(1))])
          },
          want: { sw: '6987/6984', msg: '' },
        },
        {
          label: '0x03 open, then 0x04',
          send: async t => sendAll(t, [FIRST_03, apdu(0x04, 0, hashPayload)]),
          want: { sw: '6987', msg: '' },
        },
        {
          label: '0x03 open, then 0x10',
          send: async t => sendAll(t, [FIRST_03, coinTransfer]),
          want: { sw: '6987', msg: '' },
        },
        {
          label: '0x10 open, then 0x03',
          send: async t => sendAll(t, [longLegacyTransfer()[0], FIRST_03]),
          want: { sw: '6987', msg: '' },
        },
      )
      expect(await refuseAll(m, shapes, true)).toEqual([])
    },
    1200000,
  )

  // An address command for another path between the chunks does not change the key that signs.
  test.concurrent.each(models)('%s signs a 0x22 stream with its own path after a legacy 0x02 for another path', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const pk = (await new KadenaApp(sim.getTransport()).getAddressAndPubKey(PATH, false)).pubkey
      const json = Buffer.from(CONTROL_TRANSFER, 'utf-8')
      const injected: Reply[] = []
      const app = new KadenaApp(injectAfterFirst(sim, INS_SIGN, LEGACY_GET_PUBKEY_ALT, injected))
      const signature = app.sign(PATH, json).then((r: any) => r.signature as Buffer)
      signature.catch(() => undefined)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.navigateUntilText('.', `tmp-${m.prefix.toLowerCase()}-v7-22`, sim.startOptions.approveKeyword, true, false)
      expect(injected.length).toEqual(1)
      expect(injected[0].sw).toEqual('9000')
      expect(ed25519.verify(await signature, blake(json), pk)).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('%s builds and signs a 0x24 transfer with its own path after a legacy 0x02', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const pk = (await new KadenaApp(sim.getTransport()).getAddressAndPubKey(PATH, false)).pubkey
      const params = { ...TRANSACTIONS_TEST_CASES.find(c => c.name === 'transfer_1')!.txParams }
      const injected: Reply[] = []
      const app = new KadenaApp(injectAfterFirst(sim, INS_SIGN_TRANSFER, LEGACY_GET_PUBKEY_ALT, injected))
      const req = app.signTransferTx(PATH, params as any)
      const catcher = req.catch((e: any) => e)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.navigateUntilText('.', `tmp-${m.prefix.toLowerCase()}-v7-24`, sim.startOptions.approveKeyword, true, false)
      const res: any = await catcher
      expect(injected.length).toEqual(1)
      expect(injected[0].sw).toEqual('9000')
      // The library builds the command with the key of PATH: it verifies only if the device built and
      // signed it with that key too.
      const hash = decodeHash(res.pact_command.hash)
      expect(blake(Buffer.from(res.pact_command.cmd, 'utf-8'))).toEqual(hash)
      expect(ed25519.verify(Buffer.from(res.pact_command.sigs[0].sig, 'hex'), hash, pk)).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)(
    '%s signs a two-APDU legacy 0x10 transfer with its own path after a 0x21 for another path',
    async function (m) {
      const sim = new Zemu(m.path)
      try {
        await sim.start({ ...defaultOptions, model: m.name })
        // A token transfer (two APDUs long): Blind signing on (S13).
        await sim.toggleBlindSigning()
        const pk = Buffer.from((await new KadenaApp(sim.getTransport()).getAddressAndPubKey(PATH, false)).pubkey).toString('hex')
        const data = HANDLER_LEGACY_TEST_CASES.find(c => c.name === 'handler_legacy_len_287')!
        const injected: Reply[] = []
        const app = new Kda(injectAfterFirst(sim, INS_LEGACY_TRANSFER, GET_ADDR_ALT, injected))
        const req = (app as any)['signTransferTx'](data.txParams)
        const catcher = req.catch((e: any) => e)
        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
        await sim.navigateUntilText(
          '.',
          `tmp-${m.prefix.toLowerCase()}-v7-10`,
          sim.startOptions.approveKeyword,
          true,
          false,
          0,
          30000,
          true,
          true,
          true,
        )
        const res: any = await catcher
        expect(injected.length).toEqual(1)
        expect(injected[0].sw).toEqual('9000')
        // The device returns the key that signed: the transfer's own, not the 0x21 one.
        expect(res.pubkey).toEqual(pk)
        const hash = decodeHash(res.pact_command.hash)
        expect(ed25519.verify(Buffer.from(res.pact_command.sigs[0].sig, 'hex'), hash, Buffer.from(pk, 'hex'))).toEqual(true)
      } finally {
        await sim.close()
      }
    },
  )
})

describe('v1.3.2 rule 2: one JSON value', function () {
  test.concurrent.each(models)(
    '%s refuses bytes after the value and a NUL byte (0x22 and legacy 0x03)',
    async function (m) {
      const shapes: Shape[] = ONE_VALUE_REFUSED.flatMap(c => [
        {
          label: `${c.name} 0x22`,
          send: (t: Transport) => signJsonReply(t, Buffer.from(c.json, 'utf-8')),
          want: { sw: '6984', msg: c.msg },
        },
        { label: `${c.name} 0x03`, send: (t: Transport) => legacySignJsonReply(t, Buffer.from(c.json, 'utf-8')), want: BARE_REFUSAL },
      ])
      expect(await refuseAll(m, shapes)).toEqual([])
    },
    1200000,
  )

  test.concurrent.each(models)('%s still signs a transaction followed by whitespace', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const pk = (await new KadenaApp(sim.getTransport()).getAddressAndPubKey(PATH, false)).pubkey
      const json = Buffer.from(TRAILING_WHITESPACE, 'utf-8')
      const { signature } = await reviewAndApprove(sim, m, json)
      expect(ed25519.verify(await signature, blake(json), pk)).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

describe('v1.3.2 rule 3: a signature no capability list on screen bounds is blind signing', function () {
  test.concurrent.each(models)(
    '%s refuses each with Blind signing off (0x22 and legacy 0x03)',
    async function (m) {
      let sim = new Zemu(m.path)
      const failures: string[] = []
      try {
        await sim.start({ ...defaultOptions, model: m.name })
        for (const c of UNBOUNDED) {
          for (const legacy of [false, true]) {
            const label = `${c.name} ${legacy ? '0x03' : '0x22'}`
            const t = sim.getTransport()
            const json = Buffer.from(c.json, 'utf-8')
            // The blind-signing screen, then "Blind signing mode required" + 0x6984 (0x03 too).
            const got = await (async () => {
              const last = legacy ? await legacySendAllButLast(t, json) : await sendAllButLast(t, json)
              return lastReply(sim, m, last, true)
            })().catch((e: any) => ({ sw: 'error', msg: String(e?.message ?? e) }))
            if (got.sw === BLIND_REFUSAL.sw && got.msg === BLIND_REFUSAL.msg) continue
            failures.push(`${label}: got ${got.sw} "${got.msg}"`)
            await sim.close()
            sim = new Zemu(m.path)
            await sim.start({ ...defaultOptions, model: m.name })
          }
        }
        expect(await exchangeSW(sim.getTransport(), GET_VERSION)).toEqual('9000')
      } finally {
        await sim.close()
      }
      expect(failures).toEqual([])
    },
    1200000,
  )

  // With the setting on, a meta with an unknown key is reviewed with the CAUTION and signs.
  test.concurrent.each(models)('%s reviews and signs an unrecognised meta with Blind signing on', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      await sim.toggleBlindSigning()
      const pk = (await new KadenaApp(sim.getTransport()).getAddressAndPubKey(PATH, false)).pubkey
      const json = Buffer.from(PERMUTED_META_UNKNOWN_KEY, 'utf-8')
      const { signature } = await reviewAndApprove(sim, m, json, true)
      expect(await seenCollapsed(sim)).toMatch(/'meta'fieldoftransactionnotrecognized/)
      expect(ed25519.verify(await signature, blake(json), pk)).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

describe('v1.3.2: a meta in any key order is recognised', function () {
  // The literal output of @kadena/client 1.18.3 for a plain coin transfer: clear-signed with Blind
  // signing off, no CAUTION, signature verified.
  test.concurrent.each(models)('%s clear-signs a coin transfer built by @kadena/client 1.18.3', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const pk = (await new KadenaApp(sim.getTransport()).getAddressAndPubKey(PATH, false)).pubkey
      const json = Buffer.from(KADENA_CLIENT_1_18_3_COIN_TRANSFER, 'utf-8')
      expect(blake(json).toString('base64url')).toEqual('HY0iK3awqWBbXADTBvUAQAqpdvpZRdDdXiy0wu1ybrM')
      const { signature } = await reviewAndApprove(sim, m, json)
      const seen = await seenCollapsed(sim)
      expect(seen).not.toMatch(/CAUTION|notrecognized/)
      expect(seen).toContain('atmost2500atprice1e-8')
      expect(ed25519.verify(await signature, blake(json), pk)).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  // The order the device's own templates and the legacy host library write still clear-signs.
  test.concurrent.each(models)('%s still clear-signs the canonical meta order over 0x22 and 0x03', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const pk = (await new KadenaApp(sim.getTransport()).getAddressAndPubKey(PATH, false)).pubkey
      const json = Buffer.from(CONTROL_TRANSFER, 'utf-8')
      const { signature } = await reviewAndApprove(sim, m, json)
      expect(ed25519.verify(await signature, blake(json), pk)).toEqual(true)
      expect(ed25519.verify(await legacySignJsonApproved(sim, json), blake(json), pk)).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

describe('v1.3.2 rule 4: bytes outside printable ASCII are shown as \\xNN', function () {
  test.concurrent.each(models)('%s shows the receiver escaped and signs the bytes sent', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const pk = (await new KadenaApp(sim.getTransport()).getAddressAndPubKey(PATH, false)).pubkey
      const json = Buffer.from(ESCAPED_RECEIVER, 'utf-8')
      const app = new KadenaApp(sim.getTransport())
      const req = app.sign(PATH, json)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-v132_escaped_receiver`)
      const r: any = await req
      expect(await seenCollapsed(sim)).toContain(INVISIBLE_RECEIVER_SHOWN)
      expect(ed25519.verify(r.signature, blake(json), pk)).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

describe('v1.3.2 rule 5: transfer amount precision and form', function () {
  test.concurrent.each(models)(
    '%s refuses more than 12 places, and a structured amount without a fraction',
    async function (m) {
      const structured = (amount: string, extra: Partial<TransferFields> = {}) =>
        transferBlob({ ...TRANSFER_OK, amount, ...extra } as TransferFields, 0)
      const token = { namespace: TOKEN_NAMESPACE, module: TOKEN_MODULE }
      const shapes: Shape[] = [
        ...AMOUNT_PRECISION_REFUSED.flatMap(c => [
          { label: `${c.name} 0x22`, send: (t: Transport) => signJsonReply(t, Buffer.from(c.json, 'utf-8')), want: PARSE_REFUSAL },
          { label: `${c.name} 0x03`, send: (t: Transport) => legacySignJsonReply(t, Buffer.from(c.json, 'utf-8')), want: BARE_REFUSAL },
        ]),
        ...[
          { name: 'coin 1000', blob: structured('1000') },
          { name: 'coin 0', blob: structured('0') },
          { name: 'coin 13 places', blob: structured('1.0000000000001') },
          { name: 'token 1000', blob: structured('1000', token) },
        ].flatMap(c => [
          { label: `structured ${c.name} 0x24`, send: (t: Transport) => signTransferReply(t, c.blob), want: PARSE_REFUSAL },
          {
            label: `structured ${c.name} 0x10`,
            send: (t: Transport) => reply(t, apdu(INS_LEGACY_TRANSFER, 0, Buffer.concat([LEGACY_PATH, c.blob]))),
            want: BARE_REFUSAL,
          },
        ]),
      ]
      expect(await refuseAll(m, shapes)).toEqual([])
    },
    1200000,
  )

  test.concurrent.each(models)('%s still signs an amount with 12 places', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const pk = (await new KadenaApp(sim.getTransport()).getAddressAndPubKey(PATH, false)).pubkey
      const json = Buffer.from(AMOUNT_12_PLACES, 'utf-8')
      const { signature } = await reviewAndApprove(sim, m, json)
      expect(await seenCollapsed(sim)).toContain('KDA1.000000000001')
      expect(ed25519.verify(await signature, blake(json), pk)).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

describe('v1.3.2 rules 6 and 7: verifiers, integer gas fields', function () {
  test.concurrent.each(models)(
    '%s refuses a verifiers field and non-integer gasLimit, ttl, creationTime',
    async function (m) {
      const shapes: Shape[] = [
        ...VERIFIERS.flatMap(c => [
          {
            label: `verifiers ${c.name} 0x22`,
            send: (t: Transport) => signJsonReply(t, Buffer.from(c.json, 'utf-8')),
            want: { sw: '6984', msg: 'Unexpected value' },
          },
          {
            label: `verifiers ${c.name} 0x03`,
            send: (t: Transport) => legacySignJsonReply(t, Buffer.from(c.json, 'utf-8')),
            want: BARE_REFUSAL,
          },
        ]),
        ...NON_INTEGER_META.flatMap(c => [
          { label: `${c.name} 0x22`, send: (t: Transport) => signJsonReply(t, Buffer.from(c.json, 'utf-8')), want: PARSE_REFUSAL },
          { label: `${c.name} 0x03`, send: (t: Transport) => legacySignJsonReply(t, Buffer.from(c.json, 'utf-8')), want: BARE_REFUSAL },
        ]),
      ]
      expect(await refuseAll(m, shapes)).toEqual([])
    },
    1200000,
  )
})

describe('v1.3.2: a touch-screen review must fit the display', function () {
  const touch = models.filter(m => isTouchDevice(m.name))

  // 22 transfers: about 400 pairs, which the display's 8-bit counts would wrap (the review would end
  // early and sign items never shown). Refused before any screen, with Blind signing on or off.
  test.concurrent.each(touch)(
    '%s refuses a review far over the bound',
    async function (m) {
      expect(longReviewPages(22, REVIEW_VALUE_CHARS[m.name])).toBeGreaterThan(REVIEW_MAX_PAIRS)
      const json = Buffer.from(longReview(22), 'utf-8')
      expect(json.length).toBeLessThanOrEqual(15104)
      const shapes: Shape[] = [
        { label: '0x22', send: (t: Transport) => signJsonReply(t, json), want: { sw: '6984', msg: 'Value out of range' } },
        { label: '0x03', send: (t: Transport) => legacySignJsonReply(t, json), want: BARE_REFUSAL },
      ]
      expect(await refuseAll(m, shapes)).toEqual([])
      expect(await refuseAll(m, shapes, true)).toEqual([])
    },
    1200000,
  )

  // One pair over the bound is refused (0x22 and 0x03), whatever the Blind signing setting.
  test.concurrent.each(touch)(
    '%s refuses a review of exactly one pair more than the bound',
    async function (m) {
      const json = Buffer.from(exactReview(REVIEW_MAX_PAIRS + 1, REVIEW_VALUE_CHARS[m.name]).json, 'utf-8')
      expect(json.length).toBeLessThanOrEqual(15104)
      const shapes: Shape[] = [
        { label: '0x22', send: (t: Transport) => signJsonReply(t, json), want: { sw: '6984', msg: 'Value out of range' } },
        { label: '0x03', send: (t: Transport) => legacySignJsonReply(t, json), want: BARE_REFUSAL },
      ]
      expect(await refuseAll(m, shapes, true)).toEqual([])
      expect(await refuseAll(m, shapes)).toEqual([])
    },
    1200000,
  )

  // A review of exactly the bound, packed at about one pair per screen and with the blind-signing
  // warning pages, is walked to its last screen and signed: every receiver, the unverified
  // capability and the items after it are shown, and the screen count the device announces fits.
  test.concurrent.each(touch)(
    '%s walks every screen of a review of exactly the bound and signs it',
    async function (m) {
      const { json: text, transfers } = exactReview(REVIEW_MAX_PAIRS, REVIEW_VALUE_CHARS[m.name])
      const json = Buffer.from(text, 'utf-8')
      expect(json.length).toBeLessThanOrEqual(15104)
      const sim = new Zemu(m.path)
      try {
        await sim.start({ ...defaultOptions, model: m.name })
        await sim.toggleBlindSigning()
        const pk = (await new KadenaApp(sim.getTransport()).getAddressAndPubKey(PATH, false)).pubkey
        const app = new KadenaApp(sim.getTransport())
        const signature = app.sign(PATH, json).then((r: any) => r.signature as Buffer)
        signature.catch(() => undefined)
        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
        await sim.navigateUntilText(
          '.',
          `tmp-${m.prefix.toLowerCase()}-bound`,
          sim.startOptions.approveKeyword,
          true,
          false,
          0,
          900000,
          true,
          true,
          true,
        )
        const texts: string[] = (await sim.getEvents()).map((e: any) => e.text)
        // As many receivers were walked as were sent (first page of each, or its only page).
        expect(texts.filter(t => /^To( \(1\/\d+\))?$/.test(t)).length).toEqual(transfers)
        expect(texts.some(t => t.startsWith('Unknown Capability'))).toEqual(true)
        expect(texts).toContain('On Chain')
        expect(texts).toContain('Using Gas')
        // The screen counter ("i of n"; the emulator may report a three-digit total in two pieces, so
        // the largest one seen is the total): at most 255 screens, and the walk reached the last.
        const counters = texts.map(t => /^(\d+) of (\d+)$/.exec(t)).filter(c => c !== null) as RegExpExecArray[]
        const screens = Math.max(...counters.map(c => Number(c[2])))
        expect(screens).toBeLessThanOrEqual(255)
        expect(screens).toBeGreaterThan(REVIEW_MAX_PAIRS - 2 * transfers - 9)
        expect(Math.max(...counters.map(c => Number(c[1])))).toEqual(screens)
        console.log(`REVIEW_BOUND ${m.name}: ${REVIEW_MAX_PAIRS} pairs, ${transfers} transfers, ${screens} screens, ${json.length} bytes`)
        expect(ed25519.verify(await signature, blake(json), pk)).toEqual(true)
      } finally {
        await sim.close()
      }
    },
    1800000,
  )
})
