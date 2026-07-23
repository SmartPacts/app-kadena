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

import Zemu from '@zondax/zemu'
import { KadenaApp } from '@zondax/ledger-kadena'
import { PATH, defaultOptions, models } from './common'
import { blake2bFinal, blake2bInit, blake2bUpdate } from 'blakejs'

import { NEGATIVE_SIGN_CASES, UNKNOWN_CAP_RENDER_CASE } from './testscases/negative'

// @ts-expect-error
import ed25519 from 'ed25519-supercop'

jest.setTimeout(60000)

// Malicious transactions must fail CLOSED: the app rejects with an error status word during parse
// (before any approval screen) and — critically — stays alive. A memory-corruption crash would kill
// the Speculos process and every subsequent assertion (including the liveness getVersion) would
// throw ECONNREFUSED, so this suite is also the crash regression for the F15 memory-safety fixes.
describe.each(NEGATIVE_SIGN_CASES)('Negative sign (fail closed)', function (data) {
  test.concurrent.each(models)(`${data.name} rejects and app survives`, async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new KadenaApp(sim.getTransport())

      const txBlob = Buffer.from(data.json, 'utf-8')

      // No navigation: a parse-time rejection replies immediately with an error SW.
      await expect(app.sign(PATH, txBlob)).rejects.toThrow()

      // Liveness: the app must still answer — proves it did not crash on the malicious input.
      const resp = await app.getVersion()
      expect(resp).toHaveProperty('major')
    } finally {
      await sim.close()
    }
  })
})

// Unknown capability with a string arg: the corrected renderer uses %.*s (bounded) instead of %s
// (which over-read past the token). This is a positive case — it signs — and its snapshot pins the
// faithful on-screen arg rendering (displayed == signed).
describe('Unknown-capability arg rendering', function () {
  test.concurrent.each(models)('renders faithfully and signs', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new KadenaApp(sim.getTransport())

      const txBlob = Buffer.from(UNKNOWN_CAP_RENDER_CASE.json, 'utf-8')
      const responseAddr = await app.getAddressAndPubKey(UNKNOWN_CAP_RENDER_CASE.path, false)
      const pubKey = responseAddr.pubkey

      const signatureRequest = app.sign(UNKNOWN_CAP_RENDER_CASE.path, txBlob)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-${UNKNOWN_CAP_RENDER_CASE.name}`)

      const signatureResponse = await signatureRequest

      const context = blake2bInit(32)
      blake2bUpdate(context, txBlob)
      const hash = Buffer.from(blake2bFinal(context))

      const valid = ed25519.verify(signatureResponse.signature, hash, pubKey)
      expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})
