/** ******************************************************************************
 *  (c) 2018 - 2024 Zondax AG
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

import Zemu, { ButtonKind, isTouchDevice, TouchNavigation, ClickNavigation } from '@zondax/zemu'
import Kda from '@zondax/hw-app-kda'
import { PATH, defaultOptions, models } from './common'
import { blake2bFinal, blake2bInit, blake2bUpdate } from 'blakejs'

import { JSON_TEST_CASES } from './testscases/json'
import { HASH_TEST_CASES } from './testscases/hash'
import { TRANSACTIONS_TEST_CASES, HANDLER_LEGACY_TEST_CASES } from './testscases/transactions'
import { APDU_TEST_CASES } from './testscases/legacy_apdu'
import { IButton } from '@zondax/zemu/dist/types'
import { getTouchElement } from '@zondax/zemu/dist/buttons'

// @ts-expect-error
import ed25519 from 'ed25519-supercop'

jest.setTimeout(60000)

export enum TransferTxType {
  TRANSFER = 0,
  TRANSFER_CREATE = 1,
  TRANSFER_CROSS_CHAIN = 2,
}

const expected_pk = 'de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad'

test.concurrent.each(models)('get app version', async function (m) {
  const sim = new Zemu(m.path)
  try {
    await sim.start({ ...defaultOptions, model: m.name })
    const app = new Kda(sim.getTransport())

    const resp = await app.getVersion()
    console.log(resp)

    expect(resp).toHaveProperty('major')
    expect(resp).toHaveProperty('minor')
    expect(resp).toHaveProperty('patch')
  } finally {
    await sim.close()
  }
})

test.concurrent.each(models)('get address', async function (m) {
  const sim = new Zemu(m.path)
  try {
    await sim.start({ ...defaultOptions, model: m.name })
    const app = new Kda(sim.getTransport())

    const responseAddr = await app.getPublicKey(PATH)
    const pubKey = responseAddr.publicKey
    console.log(pubKey)

    // The address is not checked because the public key is used as an address in the app
    expect(Buffer.from(pubKey).toString('hex')).toEqual(expected_pk)
  } finally {
    await sim.close()
  }
})

test.concurrent.each(models)('legacy show address', async function (m) {
  const sim = new Zemu(m.path)
  try {
    await sim.start({
      ...defaultOptions,
      model: m.name,
      approveKeyword: isTouchDevice(m.name) ? 'Confirm' : '',
      approveAction: ButtonKind.ApproveTapButton,
    })
    const app = new Kda(sim.getTransport())

    const responseAddr = app.verifyAddress(PATH)

    // Wait until we are not in the main menu
    await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
    await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_address-legacy`)

    const resp = await responseAddr
    console.log(resp)

    // The address is not checked because the public key is used as an address in the app
    expect(Buffer.from(resp.publicKey).toString('hex')).toEqual(expected_pk)
  } finally {
    await sim.close()
  }
})

test.concurrent.each(models)('legacy show address - reject', async function (m) {
  const sim = new Zemu(m.path)
  try {
    await sim.start({
      ...defaultOptions,
      model: m.name,
      approveKeyword: isTouchDevice(m.name) ? 'Confirm' : '',
      approveAction: ButtonKind.ApproveTapButton,
    })
    const app = new Kda(sim.getTransport())

    const respRequest = app.verifyAddress(PATH)

    expect(respRequest).rejects.toMatchObject(new Error('Ledger device: UNKNOWN_ERROR (0x6986)'))

    // Wait until we are not in the main menu
    await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
    await sim.compareSnapshotsAndReject('.', `${m.prefix.toLowerCase()}-show_address_reject_legacy`)
  } finally {
    await sim.close()
  }
})

describe.each(JSON_TEST_CASES)('Tx json', function (data) {
  test.concurrent.each(models)('sign json', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new Kda(sim.getTransport())

      const txBlob = Buffer.from(data.json, 'utf-8')
      const { publicKey } = await app.getPublicKey(data.path)

      // do not wait here.. we need to navigate
      const signatureRequest = app.signTransaction(data.path, txBlob)

      // // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_${data.name}_legacy`)

      const signatureResponse = await signatureRequest

      console.log('Pubkey: ', Buffer.from(publicKey).toString('hex'))
      console.log('Signature: ', Buffer.from(signatureResponse.signature).toString('hex'))

      if (signatureResponse) {
        const context = blake2bInit(32)
        blake2bUpdate(context, txBlob)
        const hash = Buffer.from(blake2bFinal(context))

        // Now verify the signature
        const valid = ed25519.verify(signatureResponse.signature, hash, publicKey)
        expect(valid).toEqual(true)
      } else {
        throw new Error('signatureResponse is null')
      }
    } finally {
      await sim.close()
    }
  })
})

describe.each(HASH_TEST_CASES)('Hash transactions', function (data) {
  test.concurrent.each(models)('sign hash', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new Kda(sim.getTransport())

      const { publicKey } = await app.getPublicKey(data.path)

      await sim.toggleBlindSigning()

      // do not wait here... we need to navigate
      const signatureRequest = app.signHash(data.path, data.hash)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_${data.name}_legacy`, true, 0, 15000, true)

      const signatureResponse = await signatureRequest

      const rawHash = data.hash.length == 64 ? Buffer.from(data.hash, 'hex') : Buffer.from(data.hash, 'base64')

      console.log('Pubkey: ', Buffer.from(publicKey).toString('hex'))
      console.log('Signature: ', Buffer.from(signatureResponse.signature).toString('hex'))
      console.log('Raw Hash: ', rawHash.toString('hex'))

      // Now verify the signature
      const valid = ed25519.verify(signatureResponse.signature, rawHash, publicKey)
      expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

describe.each(HASH_TEST_CASES)('Hash transactions BLS off', function (data) {
  test.concurrent.each(models)('sign hash', async function (m) {
    if (!isTouchDevice(m.name)) {
      return
    }
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new Kda(sim.getTransport())

      const { publicKey } = await app.getPublicKey(data.path)

      const signNonExpert = app.signHash(data.path, data.hash)
      // Attach the rejection matcher before navigating so an early device
      // reply cannot surface as an unhandled rejection
      const signAssertion = expect(signNonExpert).rejects.toThrow('Ledger device: UNKNOWN_ERROR (0x6984)')

      await Zemu.sleep(500)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      let nav = undefined
      const confirmButton: IButton = getTouchElement(m.name, ButtonKind.ConfirmYesButton)
      nav = new TouchNavigation(m.name, [ButtonKind.ConfirmYesButton])
      nav.schedule[0].button = confirmButton

      await sim.navigate('.', `${m.prefix.toLowerCase()}-clear_sign_${data.name}_legacy`, nav.schedule)

      await signAssertion
    } finally {
      await sim.close()
    }
  })
})

describe.each(TRANSACTIONS_TEST_CASES)('Tx transfer', function (data) {
  test.concurrent.each(models)('sign transfer tx', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new Kda(sim.getTransport())

      const { publicKey } = await app.getPublicKey(data.txParams.path)

      // do not wait here... we need to navigate
      var signatureRequest = null
      if (data.type === TransferTxType.TRANSFER) {
        signatureRequest = app['signTransferTx'](data.txParams)
      } else if (data.type === TransferTxType.TRANSFER_CREATE) {
        signatureRequest = app['signTransferCreateTx'](data.txParams)
      } else if (data.type === TransferTxType.TRANSFER_CROSS_CHAIN) {
        signatureRequest = app['signTransferCrossChainTx'](data.txParams)
      }

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_${data.name}_legacy`)

      // Wait until we are not in the main menu
      const signatureResponse = await signatureRequest

      console.log(signatureResponse)

      if (signatureResponse) {
        const signatureHex = signatureResponse.pact_command.sigs[0].sig
        const decodedHash = decodeHash(signatureResponse.pact_command.hash)
        console.log('Pubkey: ', Buffer.from(publicKey).toString('hex'))
        console.log('Signature: ', Buffer.from(signatureHex).toString('hex'))
        console.log('Decoded Hash: ', Buffer.from(decodedHash).toString('hex'))

        // Now verify the signature
        const valid = ed25519.verify(signatureHex, decodedHash, publicKey)
        expect(valid).toEqual(true)
      } else {
        throw new Error('signatureResponse is null')
      }
    } finally {
      await sim.close()
    }
  })
})

describe.each(HANDLER_LEGACY_TEST_CASES)('Tx transfer', function (data) {
  test.concurrent.each(models)('apdu legacy test', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new Kda(sim.getTransport())

      const { publicKey } = await app.getPublicKey(data.txParams.path)

      // do not wait here... we need to navigate
      var signatureRequest = null
      if (data.type === TransferTxType.TRANSFER) {
        signatureRequest = app['signTransferTx'](data.txParams)
      } else if (data.type === TransferTxType.TRANSFER_CREATE) {
        signatureRequest = app['signTransferCreateTx'](data.txParams)
      } else if (data.type === TransferTxType.TRANSFER_CROSS_CHAIN) {
        signatureRequest = app['signTransferCrossChainTx'](data.txParams)
      }

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-${data.name}`)

      // Wait until we are not in the main menu
      const signatureResponse = await signatureRequest

      console.log(signatureResponse)

      if (signatureResponse) {
        const signatureHex = signatureResponse.pact_command.sigs[0].sig
        const decodedHash = decodeHash(signatureResponse.pact_command.hash)
        console.log('Pubkey: ', Buffer.from(publicKey).toString('hex'))
        console.log('Signature: ', Buffer.from(signatureHex).toString('hex'))
        console.log('Decoded Hash: ', Buffer.from(decodedHash).toString('hex'))

        // Now verify the signature
        const valid = ed25519.verify(signatureHex, decodedHash, publicKey)
        expect(valid).toEqual(true)
      } else {
        throw new Error('signatureResponse is null')
      }
    } finally {
      await sim.close()
    }
  })
})

describe.each(APDU_TEST_CASES)('APDU tests ', function (data) {
  test.concurrent.each(models)('legacy apdu test', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new Kda(sim.getTransport())

      const txBlob = Buffer.from(data.json, 'utf-8')

      const { publicKey } = await app.getPublicKey(data.path)

      // do not wait here... we need to navigate
      var signatureRequest = app.signTransaction(data.path, txBlob)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-${data.name}`)

      // Wait until we are not in the main menu
      const signatureResponse = await signatureRequest

      if (signatureResponse) {
        const context = blake2bInit(32)
        blake2bUpdate(context, txBlob)
        const hash = Buffer.from(blake2bFinal(context))

        // Now verify the signature
        const valid = ed25519.verify(signatureResponse.signature, hash, publicKey)
        expect(valid).toEqual(true)
      } else {
        throw new Error('signatureResponse is null')
      }
    } finally {
      await sim.close()
    }
  })
})

// F15 HIGH-A regression: the legacy HD-path guard [2, HDPATH_LEN_DEFAULT]. A host-controlled
// hdPathQty must NEVER drive the MEMCPY past the fixed 20-byte hdPath global (qty > 5) and must cover
// the two components the mainnet check reads (qty >= 2). @zondax/hw-app-kda cannot encode an
// out-of-range path, so these send RAW BCOMP_GET_PUBKEY (0x02) APDUs via the transport and assert the
// status word directly. Layout: CLA(00) INS(02) P1(00) P2(00) Lc | hdPathQty | hdPathQty*4 path bytes.
const COMP_LE = [0x8000002c, 0x80000272, 0x80000000, 0x00000000, 0x00000000] // m/44'/626'/0'/0/0
function u32le(n: number): Buffer {
  const b = Buffer.alloc(4)
  b.writeUInt32LE(n >>> 0, 0)
  return b
}
function getPubkeyApdu(qty: number, comps: number[]): Buffer {
  const path = Buffer.concat(comps.map(u32le))
  const lc = 1 + path.length
  return Buffer.concat([Buffer.from([0x00, 0x02, 0x00, 0x00, lc & 0xff, qty & 0xff]), path])
}
// The Zemu transport THROWS on a non-0x9000 status word (TransportStatusError.statusCode), so
// normalize both outcomes to the 4-hex status string.
async function sw(sim: Zemu, apdu: Buffer): Promise<string> {
  try {
    const resp = await sim.getTransport().exchange(apdu)
    return resp.subarray(-2).toString('hex')
  } catch (e: any) {
    if (typeof e?.statusCode === 'number') return e.statusCode.toString(16).padStart(4, '0')
    throw e
  }
}

const HDPATH_GUARD_CASES = [
  { name: 'overflow qty=63 rejected', qty: 63, comps: Array.from({ length: 63 }, (_, i) => COMP_LE[i % 5]), want: '6984' },
  { name: 'overflow qty=6 rejected', qty: 6, comps: Array.from({ length: 6 }, (_, i) => COMP_LE[i % 5]), want: '6984' },
  { name: 'under-min qty=1 rejected', qty: 1, comps: [COMP_LE[0]], want: '6984' },
  { name: 'valid qty=5 accepted', qty: 5, comps: COMP_LE, want: '9000' },
  { name: 'valid qty=2 (m/44/626) accepted', qty: 2, comps: [COMP_LE[0], COMP_LE[1]], want: '9000' },
]

describe.each(HDPATH_GUARD_CASES)('Legacy HD-path guard', function (data) {
  test.concurrent.each(models)(`${data.name}`, async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const got = await sw(sim, getPubkeyApdu(data.qty, data.comps))
      expect(got).toEqual(data.want)
      // The app must survive an overflow attempt: GET_VERSION (0x00 0x20) still answers 0x9000.
      const alive = await sw(sim, Buffer.from([0x00, 0x20, 0x00, 0x00, 0x00]))
      expect(alive).toEqual('9000')
    } finally {
      await sim.close()
    }
  })
})

function decodeHash(encodedHash: string) {
  let base64Hash = encodedHash.replace(/-/g, '+').replace(/_/g, '/')

  while (base64Hash.length % 4) {
    base64Hash += '='
  }

  return Buffer.from(base64Hash, 'base64')
}
