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

import Zemu, { ButtonKind, isTouchDevice } from '@zondax/zemu'
import { KadenaApp } from '@zondax/ledger-kadena'
import { PATH, defaultOptions, models } from './common'
import { getTouchElement } from '@zondax/zemu/dist/buttons'
import { IButton } from '@zondax/zemu/dist/types'

import { NEGATIVE_SIGN_CASES, UNKNOWN_CAP_RENDER_CASE } from './testscases/negative'

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

// Unknown capability with a string arg. Since v1.3.1 (S10) a capability the device does not
// fully render is NOT clear-signed: it requires the Blind signing setting and, with it off, is
// refused. The faithful bounded arg rendering (trap-19 fix) is pinned by the C++ unit vectors
// (tests/testcases.json arbitrary_cap_*). Here we assert the refusal with Blind signing off:
// the blind-signing screen, then 0x6984.
describe('Unknown capability requires blind signing', function () {
  test.concurrent.each(models)('refuses with Blind signing off', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new KadenaApp(sim.getTransport())
      const refusal = app.sign(UNKNOWN_CAP_RENDER_CASE.path, Buffer.from(UNKNOWN_CAP_RENDER_CASE.json, 'utf-8'))
      const assertion = expect(refusal).rejects.toMatchObject({
        returnCode: 0x6984,
        errorMessage: expect.stringContaining('Blind signing mode required'),
      })
      // The refusal is reported on screen and the reply is deferred until the user dismisses it.
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      // The refusal's reply (0x6984) can arrive while Zemu still waits for the screen to repaint, and
      // Zemu then aborts that wait with a 0x6984 transport error; only that error is tolerated.
      try {
        if (isTouchDevice(m.name)) {
          await sim.fingerTouch(getTouchElement(m.name, ButtonKind.RejectButton) as IButton)
        } else {
          await sim.waitForText('Blind signing must be')
          await sim.clickBoth()
        }
      } catch (e: any) {
        if (e?.statusCode !== 0x6984) throw e
      }
      await assertion
      // The app survives.
      const v = await app.getVersion()
      expect(v).toHaveProperty('major')
    } finally {
      await sim.close()
    }
  })
})
