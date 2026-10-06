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

// Inputs for the v1.3.1 regression tests (security.test.ts). Each one is refused, or reviewed with a
// warning, by v1.3.1, and was signed or reviewed without the warning by v1.3.0.

// Device key for m/44'/626'/0'/0/0 with the test seed.
export const DEVICE = 'de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad'
// Some other signer key.
export const OTHER = '83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790'
const RECIPIENT = '9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42'

const META = `{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"k:${DEVICE}"}`
const GAS = '{"args":[],"name":"coin.GAS"}'
const transfer = (from: string, amount = '1.0') => `{"args":["${from}","k:${RECIPIENT}",${amount}],"name":"coin.TRANSFER"}`
const TRANSFER_CODE = `(coin.transfer \\"k:${DEVICE}\\" \\"k:${RECIPIENT}\\" 1.0)`
const ROTATE_CODE = '(coin.rotate \\"alice\\" (read-keyset \\"new\\"))'

export const command = (signers: string, code = TRANSFER_CODE) =>
  `{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"${code}"}},"signers":${signers},"meta":${META},"nonce":"n"}`

// ---- Structured transfer fields (INS 0x24 and legacy 0x10) --------------------------------------

export const TRANSFER_FIELD_ORDER = [
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
  'ttl',
] as const
export type TransferFields = Record<(typeof TRANSFER_FIELD_ORDER)[number], string>

export const TRANSFER_OK: TransferFields = {
  recipient: 'a'.repeat(64),
  recipient_chain: '0',
  network: 'mainnet01',
  amount: '1.0',
  namespace: '',
  module: '',
  gas_price: '1.0e-6',
  gas_limit: '600',
  creation_time: '0',
  chain_id: '0',
  nonce: 'n',
  ttl: '28800',
}

// tx_type byte + 12 x (len, bytes)
export function transferBlob(fields: TransferFields, txType = 0): Buffer {
  const parts: Buffer[] = [Buffer.from([txType])]
  for (const k of TRANSFER_FIELD_ORDER) {
    const v = Buffer.from(fields[k], 'latin1')
    parts.push(Buffer.from([v.length]), v)
  }
  return Buffer.concat(parts)
}

// Each value passes the length caps but not the field's content rule: refused with
// "Unexpected characters" (0x24) or a bare 0x6984 (legacy 0x10).
export const TRANSFER_FIELD_REJECTS: { name: string; fields: Partial<TransferFields>; txType?: number }[] = [
  { name: 'nonce closes the JSON string', fields: { nonce: 'x","injected":"HID' } },
  { name: 'nonce backslash', fields: { nonce: 'a\\b' } },
  { name: 'nonce control byte', fields: { nonce: 'a\nb' } },
  { name: 'amount adds JSON', fields: { amount: '1,"evil":9' } },
  { name: 'amount trailing dot', fields: { amount: '1.' } },
  { name: 'amount empty', fields: { amount: '' } },
  { name: 'amount negative', fields: { amount: '-1.0' } },
  { name: 'namespace quote', fields: { namespace: 'a","b":"c', module: 'm' } },
  { name: 'module dot', fields: { namespace: 'free', module: 'a.b' } },
  { name: 'recipient quote', fields: { recipient: 'a","x":"' + 'a'.repeat(56) } },
  { name: 'recipient uppercase hex', fields: { recipient: 'A'.repeat(64) } },
  { name: 'gas limit exponent', fields: { gas_limit: '1e3' } },
  { name: 'gas price empty exponent', fields: { gas_price: '1.0e' } },
  { name: 'creation time sign', fields: { creation_time: '+1' } },
  { name: 'ttl space', fields: { ttl: '28800 ' } },
  // Already refused by v1.3.0 (with another message); kept to pin the v1.3.1 refusal.
  { name: 'chain id empty', fields: { chain_id: '' } },
  { name: 'chain id letter', fields: { chain_id: 'a' } },
  { name: 'network space', fields: { network: 'main net' } },
  // An exponent amount: the allowlist admits only plain decimals in the amount field, so S11 (which
  // refuses exponents in host-built JSON) can never be reached through 0x24 / 0x10.
  { name: 'amount exponent', fields: { amount: '1e3' } },
  // Already refused by v1.3.0 (with another message); kept to pin the v1.3.1 refusal.
  { name: 'cross-chain target empty', fields: { recipient_chain: '' }, txType: 2 },
]

// Accepted by both v1.3.0 and v1.3.1 (grammar edges that stay valid).
export const TRANSFER_FIELD_EDGE_OK: TransferFields = {
  ...TRANSFER_OK,
  recipient: '0123456789abcdef'.repeat(4),
  network: 'dev-net_0.1',
  amount: '0.000000000001',
  gas_price: '1E+2',
  gas_limit: '0',
  nonce: " !#$%&'()*+,-./:;<=>?@[]^_`{|}~",
}

// ---- JSON (INS 0x22 / legacy 0x03) ----------------------------------------------------------------

// S4: the capability's sender is the device key followed by more characters (another account).
export const PREFIX_SENDER = command(`[{"pubKey":"${DEVICE}","clist":[${transfer('k:' + DEVICE + 'ff')},${GAS}]}]`)

// S5: an empty capability list (Pact: valid for any capability).
export const EMPTY_CLIST = command(`[{"pubKey":"${DEVICE}","clist":[]}]`)

// S6: the device key is the second signer; signers[0] is another key with a harmless list.
export const DEVICE_SECOND = command(
  `[{"pubKey":"${OTHER}","clist":[${GAS}]},{"pubKey":"${DEVICE}","clist":[${transfer('k:' + DEVICE)},${GAS}]}]`,
)
// S6: two entries for the device key (Pact keeps the last one).
export const DEVICE_TWICE = command(
  `[{"pubKey":"${DEVICE}","clist":[${transfer('k:' + DEVICE)},${GAS}]},{"pubKey":"${DEVICE}","clist":[${transfer('k:' + DEVICE, '1000.0')},${GAS}]}]`,
)
// S6: the device key is not a signer.
export const DEVICE_ABSENT = command(`[{"pubKey":"${OTHER}","clist":[${transfer('k:' + OTHER)},${GAS}]}]`)

// S7: the device entry holds coin.ROTATE (the new owner comes from undisplayed code and data).
export const ROTATE = command(`[{"pubKey":"${DEVICE}","clist":[${GAS},{"args":["alice"],"name":"coin.ROTATE"}]}]`, ROTATE_CODE)

// ---- S10/S11: unverified capabilities and exponent amounts -------------------------------------
const INSTALL_TRANSFER = `(install-capability (coin.TRANSFER \\"k:${DEVICE}\\" \\"k:${RECIPIENT}\\" 1000.0)) (coin.transfer \\"k:${DEVICE}\\" \\"k:${RECIPIENT}\\" 1000.0)`

// The device's own signer entry with the given capability list.
const deviceScoped = (clist: string, code = TRANSFER_CODE) => command(`[{"pubKey":"${DEVICE}","clist":[${GAS},${clist}]}]`, code)

// S10: a scoped coin.DEBIT lets undisplayed code install a TRANSFER and drain the account. It, and
// coin.CREDIT, and any non-coin capability, require the Blind signing setting and carry a warning.
export const DEBIT = deviceScoped(`{"name":"coin.DEBIT","args":["k:${DEVICE}"]}`, INSTALL_TRANSFER)
export const CREDIT = deviceScoped(`{"name":"coin.CREDIT","args":["k:${RECIPIENT}"]}`, INSTALL_TRANSFER)
export const MODULE_CAP = deviceScoped(`{"name":"free.evil.STEAL","args":[]}`, INSTALL_TRANSFER)

// S11: an exponent amount reads as an exact decimal on chain but is shown raw. Refused, as a JSON
// number and inside the {"decimal":"..."} object form (whose reader also accepts an exponent).
const expTransfer = (amount: string) => deviceScoped(`{"name":"coin.TRANSFER","args":["k:${DEVICE}","k:${RECIPIENT}",${amount}]}`)
const expXchain = (amount: string) => deviceScoped(`{"name":"coin.TRANSFER_XCHAIN","args":["k:${DEVICE}","k:${RECIPIENT}",${amount},"1"]}`)
export const EXP_AMOUNTS: { name: string; json: string }[] = [
  { name: 's11_number', json: expTransfer('1.0000000001e3') },
  { name: 's11_number_xchain', json: expXchain('1e3') },
  { name: 's11_object', json: expTransfer('{"decimal":"1e3"}') },
  { name: 's11_object_xchain', json: expXchain('{"decimal":"1.0000000001E3"}') },
]

// S14 (bare number or decimal object): a coin.TRANSFER / TRANSFER_XCHAIN amount in host JSON is accepted in two
// forms only, a bare number or {"decimal":"<text>"} with that single key, where the number or text is
// digits('.' digits)? with no leading zero; the review shows the plain number.
export const AMOUNT_ACCEPTED: { name: string; json: string; shown: string }[] = [
  { name: 'bare integer', json: expTransfer('231'), shown: 'KDA 231' },
  { name: 'bare 0.5', json: expTransfer('0.5'), shown: 'KDA 0.5' },
  { name: 'decimal object', json: expTransfer('{"decimal":"231"}'), shown: 'KDA 231' },
  { name: 'decimal object 0.5', json: expTransfer('{"decimal":"0.5"}'), shown: 'KDA 0.5' },
  { name: 'decimal object, xchain', json: expXchain('{"decimal":"231"}'), shown: 'KDA 231' },
]
export const AMOUNT_REFUSED: { name: string; json: string }[] = [
  { name: 'string', json: expTransfer('"231"') },
  { name: 'int object', json: expTransfer('{"int":231}') },
  { name: 'negative', json: expTransfer('-1.0') },
  { name: 'plus sign', json: expTransfer('+1.0') },
  { name: 'trailing dot', json: expTransfer('1.') },
  { name: 'leading dot', json: expTransfer('.5') },
  { name: 'leading zero', json: expTransfer('01.0') },
  { name: 'double zero', json: expTransfer('00') },
  { name: 'object leading zero', json: expTransfer('{"decimal":"01.0"}') },
  { name: 'object empty string', json: expTransfer('{"decimal":""}') },
  { name: 'object leading dot', json: expTransfer('{"decimal":".5"}') },
  { name: 'object trailing dot', json: expTransfer('{"decimal":"1."}') },
  { name: 'object negative', json: expTransfer('{"decimal":"-1.0"}') },
  { name: 'object exponent', json: expTransfer('{"decimal":"1e3"}') },
  { name: 'object number value', json: expTransfer('{"decimal":231}') },
  { name: 'object extra key', json: expTransfer('{"decimal":"231","x":"1"}') },
  { name: 'object nested', json: expTransfer('{"decimal":{"v":"231"}}') },
  { name: 'empty object', json: expTransfer('{}') },
  { name: 'object other key', json: expTransfer('{"Decimal":"231"}') },
  { name: 'object escaped digit', json: expTransfer('{"decimal":"2\\u00331"}') },
  { name: 'object inner space', json: expTransfer('{"decimal":" 231"}') },
]

// A token module's TRANSFER in host-built JSON: refused with Blind signing off (a structured
// transfer of the same token, built by the device, is clear-signed).
export const TOKEN_NAMESPACE = 'n_e595727b657fbbb3b8e362a05a7bb8d12865c1ff'
export const TOKEN_MODULE = 'kb-USDC'
const TOKEN = `${TOKEN_NAMESPACE}.${TOKEN_MODULE}`
export const TOKEN_CAP_JSON = deviceScoped(
  `{"name":"${TOKEN}.TRANSFER","args":["k:${DEVICE}","k:${RECIPIENT}",1.0]}`,
  `(${TOKEN}.transfer \\"k:${DEVICE}\\" \\"k:${RECIPIENT}\\" 1.0)`,
)

// Capabilities the device does not fully render: refused with Blind signing off.
export const UNVERIFIED_CAPS: { name: string; json: string }[] = [
  { name: 's10_debit', json: DEBIT },
  { name: 's10_credit', json: CREDIT },
  { name: 's10_module_cap', json: MODULE_CAP },
]

// ---- S8/S9: escaped and duplicate JSON keys -------------------------------------------------------
// A JSON decoder unescapes a key before its duplicate rule, but the device compares raw key bytes.
// Each body puts an escaped (or literal duplicate) spelling that the device reads one way and the
// chain reads the other. On v1.3.0 each one is reviewed and signed with none of the hidden effect
// shown; v1.3.1 refuses them all. In these strings a source `\\u00XX` is the two bytes backslash-u
// in the JSON, i.e. a JSON escape the device must reject.

// A1: an escaped "name" turns the shown coin.GAS into a coin.TRANSFER of 1000 from the device.
export const A1_ESCAPED_NAME = `{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"k:${DEVICE}\\" \\"k:${RECIPIENT}\\" 1000.0)"}},"signers":[{"pubKey":"${DEVICE}","clist":[{"n\\u0061me":"coin.TRANSFER","args":["k:${DEVICE}","k:${RECIPIENT}",1000.0],"name":"coin.GAS"},${GAS}]}],"meta":${META},"nonce":"n"}`

// A2: an escaped "signers" before the real one hides a 1000 transfer in the entry the chain reads.
export const A2_ESCAPED_SIGNERS = `{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"k:${DEVICE}\\" \\"k:${RECIPIENT}\\" 1000.0)"}},"sign\\u0065rs":[{"pubKey":"${DEVICE}","clist":[{"args":["k:${DEVICE}","k:${RECIPIENT}",1000.0],"name":"coin.TRANSFER"},${GAS}]}],"signers":[{"pubKey":"${DEVICE}","clist":[{"args":["k:${DEVICE}","k:${RECIPIENT}",1.0],"name":"coin.TRANSFER"},${GAS}]}],"meta":${META},"nonce":"n"}`

// A3: an escaped ROTATE name value, shown as an obfuscated unknown capability, not a rotation.
export const A3_ROTATE_NAME_ESCAPED = `{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"${ROTATE_CODE}"}},"signers":[{"pubKey":"${DEVICE}","clist":[${GAS},{"args":["alice"],"name":"coin.\\u0052OTATE"}]}],"meta":${META},"nonce":"n"}`

// A4: an escaped "name" key hides the ROTATE capability entirely (shown as coin.GAS).
export const A4_ROTATE_HIDDEN_KEY = `{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"${ROTATE_CODE}"}},"signers":[{"pubKey":"${DEVICE}","clist":[${GAS},{"n\\u0061me":"coin.ROTATE","args":["alice"],"name":"coin.GAS"}]}],"meta":${META},"nonce":"n"}`

// A8: an escaped "meta" hides a 150000-limit, 0.1-price fee behind the shown normal meta.
export const A8_ESCAPED_META = `{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"k:${DEVICE}\\" \\"k:${RECIPIENT}\\" 1.0)"}},"signers":[{"pubKey":"${DEVICE}","clist":[{"args":["k:${DEVICE}","k:${RECIPIENT}",1.0],"name":"coin.TRANSFER"},${GAS}]}],"m\\u0065ta":{"creationTime":1634009214,"ttl":28800,"gasLimit":150000,"chainId":"0","gasPrice":0.1,"sender":"k:${DEVICE}"},"meta":${META},"nonce":"n"}`

// S8: a literal duplicate key (device reads the first, a last-wins decoder the second).
export const LITERAL_DUP_KEY = command(`[{"pubKey":"${DEVICE}","clist":[${transfer('k:' + DEVICE)},${GAS}]}]`).replace(
  '{"networkId":"mainnet01",',
  '{"networkId":"evilnet","networkId":"mainnet01",',
)

// Controls that must still sign.
export const CONTROL_TRANSFER = command(`[{"pubKey":"${DEVICE}","clist":[${transfer('k:' + DEVICE)},${GAS}]}]`)

// Literal duplicate keys nested below the root. A duplicate "name" inside a clist entry (the
// device reads coin.GAS, a last-wins decoder coin.TRANSFER), and a duplicate "clist" inside the
// device's signer entry. Both are refused with "Unexpected duplicated field".
export const DUP_NAME_IN_CAP = CONTROL_TRANSFER.replace(GAS, '{"name":"coin.GAS","args":[],"name":"coin.TRANSFER"}')
export const DUP_CLIST_IN_SIGNER = CONTROL_TRANSFER.replace(
  `{"pubKey":"${DEVICE}","clist":`,
  `{"pubKey":"${DEVICE}","clist":[${GAS}],"clist":`,
)
// Each attack with the message the device refuses it with over INS 0x22 (legacy 0x03 is bare).
const ESCAPE = 'Unexpected characters'
const DUPLICATE = 'Unexpected duplicated field'
export const KEY_ATTACKS: { name: string; json: string; msg: string }[] = [
  { name: 's9_a1', json: A1_ESCAPED_NAME, msg: ESCAPE },
  { name: 's9_a2', json: A2_ESCAPED_SIGNERS, msg: ESCAPE },
  { name: 's9_a3', json: A3_ROTATE_NAME_ESCAPED, msg: ESCAPE },
  { name: 's9_a4', json: A4_ROTATE_HIDDEN_KEY, msg: ESCAPE },
  { name: 's9_a8', json: A8_ESCAPED_META, msg: ESCAPE },
  { name: 's8_literal_dup', json: LITERAL_DUP_KEY, msg: DUPLICATE },
  { name: 'dup_name_in_cap', json: DUP_NAME_IN_CAP, msg: DUPLICATE },
  { name: 'dup_clist_in_signer', json: DUP_CLIST_IN_SIGNER, msg: DUPLICATE },
]

// ---- v1.3.2 ---------------------------------------------------------------------------------------
// Inputs for the v1.3.2 tests. Each refusal here was reviewed (or, for the stream cases, accepted)
// by v1.3.1; each positive case still signs.

// Rule 3: a signature that no capability list on screen bounds is blind signing. An unscoped signer
// (missing, null or empty clist) and a `meta` the device does not recognise are refused with Blind
// signing off and reviewed with it on.
export const NO_CLIST = command(`[{"pubKey":"${DEVICE}"}]`)
export const NULL_CLIST = command(`[{"pubKey":"${DEVICE}","clist":null}]`)
// The keys of a recognised `meta` may come in any order; an unknown key still makes it unrecognised.
const PERMUTED_META = `{"gasPrice":1.0e-5,"sender":"k:${DEVICE}","chainId":"0","ttl":28800,"gasLimit":600,"creationTime":1634009214}`
export const PERMUTED_META_UNKNOWN_KEY = CONTROL_TRANSFER.replace(META, PERMUTED_META.replace('}', ',"payer":"x"}'))
export const PERMUTED_META_KEY_REPLACED = CONTROL_TRANSFER.replace(META, PERMUTED_META.replace('"sender"', '"payer"'))
export const UNBOUNDED: { name: string; json: string }[] = [
  { name: 'no clist', json: NO_CLIST },
  { name: 'null clist', json: NULL_CLIST },
  { name: 'empty clist', json: EMPTY_CLIST },
  { name: 'meta with an unknown seventh key', json: PERMUTED_META_UNKNOWN_KEY },
  { name: 'meta with an unknown key in place of sender', json: PERMUTED_META_KEY_REPLACED },
]

// A plain coin transfer exactly as @kadena/client 1.18.3 writes it (Pact.builder.execution(...)
// .addSigner(...).setMeta({ chainId, senderAccount }).setNetworkId('mainnet01').createTransaction()):
// `meta` keys in the library's order, the amount as {"decimal":"1.0"}, gasPrice 1e-8. Clear-signed.
export const KADENA_CLIENT_1_18_3_COIN_TRANSFER =
  '{"payload":{"exec":{"code":"(coin.transfer \\"k:de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad\\" \\"k:9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\\" 1.0)","data":{}}},"nonce":"kjs:nonce:1791110121913","signers":[{"pubKey":"de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad","scheme":"ED25519","clist":[{"name":"coin.TRANSFER","args":["k:de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad","k:9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42",{"decimal":"1.0"}]},{"name":"coin.GAS","args":[]}]}],"meta":{"gasLimit":2500,"gasPrice":1e-8,"sender":"k:de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad","ttl":900,"creationTime":1791110121,"chainId":"0"},"networkId":"mainnet01"}'

// Rule 2: one JSON value. Bytes after it, or a NUL byte anywhere, are refused.
export const ONE_VALUE_REFUSED: { name: string; json: string; msg: string }[] = [
  { name: 'trailing object', json: CONTROL_TRANSFER + '{}', msg: 'Unexpected unparsed bytes' },
  { name: 'trailing text', json: CONTROL_TRANSFER + ' x', msg: 'Unexpected unparsed bytes' },
  { name: 'second transaction', json: CONTROL_TRANSFER + CONTROL_TRANSFER, msg: 'Unexpected unparsed bytes' },
  { name: 'NUL then JSON', json: CONTROL_TRANSFER + '\u0000{"a":1}', msg: 'Unexpected characters' },
  { name: 'NUL in a value', json: CONTROL_TRANSFER.replace('"nonce":"n"', '"nonce":"n\u0000"'), msg: 'Unexpected characters' },
]
export const TRAILING_WHITESPACE = CONTROL_TRANSFER + ' \n\t\r'

// Rule 4: a receiver whose name holds bytes a screen can draw as nothing (NBSP, soft hyphen, C1 NEL,
// DEL, a C0 control). The review shows each as \xNN; the signed bytes are unchanged.
export const INVISIBLE_RECEIVER = 'bob\u00a0x\u00ad\u007f\u0001y\u0085'
export const INVISIBLE_RECEIVER_SHOWN = 'bob\\xC2\\xA0x\\xC2\\xAD\\x7F\\x01y\\xC2\\x85'
export const ESCAPED_RECEIVER = deviceScoped(`{"name":"coin.TRANSFER","args":["k:${DEVICE}","${INVISIBLE_RECEIVER}",1.0]}`)

// Rule 5: at most 12 fractional digits in a coin transfer amount.
export const AMOUNT_PRECISION_REFUSED: { name: string; json: string }[] = [
  { name: 'bare 13 places', json: expTransfer('0.1234567890123') },
  { name: 'object 13 places', json: expTransfer('{"decimal":"1.1234567890123"}') },
  { name: 'xchain 13 places', json: expXchain('2.0000000000001') },
  { name: '256 nines', json: expTransfer('0.' + '9'.repeat(256)) },
]
export const AMOUNT_12_PLACES = expTransfer('{"decimal":"1.000000000001"}')

// Rule 6: Pact 5 signature verifiers.
export const VERIFIERS: { name: string; json: string }[] = [
  { name: 'empty', json: CONTROL_TRANSFER.replace('"nonce":"n"', '"verifiers":[],"nonce":"n"') },
  { name: 'null', json: CONTROL_TRANSFER.replace('"nonce":"n"', '"verifiers":null,"nonce":"n"') },
  {
    name: 'one verifier',
    json: CONTROL_TRANSFER.replace('"nonce":"n"', '"verifiers":[{"name":"x","proof":"p","clist":[]}],"nonce":"n"'),
  },
]

// Rule 7: gasLimit, ttl and creationTime are integers on the network.
export const NON_INTEGER_META: { name: string; json: string }[] = [
  { name: 'gasLimit 1.5', json: CONTROL_TRANSFER.replace('"gasLimit":600', '"gasLimit":1.5') },
  { name: 'gasLimit 6e2', json: CONTROL_TRANSFER.replace('"gasLimit":600', '"gasLimit":6e2') },
  { name: 'gasLimit string', json: CONTROL_TRANSFER.replace('"gasLimit":600', '"gasLimit":"600"') },
  { name: 'ttl 28800.0', json: CONTROL_TRANSFER.replace('"ttl":28800', '"ttl":28800.0') },
  { name: 'creationTime 1e3', json: CONTROL_TRANSFER.replace('"creationTime":1634009214', '"creationTime":1e3') },
]

// Rule 1 and the structured amount rules: a coin transfer long enough to need two legacy 0x10 APDUs.
export const LONG_COIN_TRANSFER: TransferFields = {
  ...TRANSFER_OK,
  recipient_chain: '10',
  network: 'mainnet01-long-name_',
  amount: '10000000000000000000.000000000000',
  gas_price: '0.000000010000000000',
  gas_limit: '2500000000',
  creation_time: '170000000000',
  chain_id: '10',
  nonce: 'x'.repeat(32),
  ttl: '28800000000000000000',
}

// The touch review shows every page of every item as one pair and may hold at most 253 pairs: the
// display layer counts pairs, and then screens (first page, pair screens, last page), in 8 bits.
export const REVIEW_MAX_PAIRS = 253
// zxlib MAX_CHARS_PER_VALUE1_LINE per touch model (a page holds one character less).
export const REVIEW_VALUE_CHARS: Record<string, number> = { stax: 160, flex: 162, apex_p: 144 }

// A clear-signed review of `n` coin transfers whose sender and receiver are 290 bytes of no-break
// spaces each: every such value is shown as 1160 characters (\xC2\xA0), 8 pages on Stax and Flex,
// 9 on Apex P.
const NBSP_ACCOUNT = '\u00a0'.repeat(145)
export const longReview = (n: number) =>
  deviceScoped(Array.from({ length: n }, () => `{"name":"coin.TRANSFER","args":["${NBSP_ACCOUNT}","${NBSP_ACCOUNT}",1.0]}`).join(','))
// Pairs of longReview(n): Signing, On Network, Requiring, Of Key, Unscoped Signer, On Chain, Using Gas,
// and per transfer its title, sender, receiver and amount.
export function longReviewPages(n: number, valueChars: number): number {
  const perValue = Math.ceil(1160 / (valueChars - 1))
  return 7 + n * (2 + 2 * perValue)
}

// A review of exactly `pairs` pairs on a touch model whose value page holds `valueChars - 1`
// characters, packed at about one pair per screen: the network, every amount and every page of
// every sender and receiver fill a page exactly, so each sits alone on its screen (as each transfer
// title between them does). An account of k pages is a few letters and then no-break spaces, each
// shown as \xC2\xA0. The entry also holds a capability the device cannot verify, so the review is a
// blind-signing one, with its warning pages.
// Pairs: Signing, On Network, Requiring, Of Key, Unscoped Signer, per transfer its title, k sender
// pages, k receiver pages and the amount, then the unverified capability and its WARNING, On Chain
// and Using Gas.
export function exactReview(pairs: number, valueChars: number): { json: string; transfers: number } {
  const page = valueChars - 1
  const account = (k: number) => {
    const nbsp = Math.floor((k * page) / 8)
    return 'a'.repeat(k * page - 8 * nbsp) + '\u00a0'.repeat(nbsp)
  }
  const bytes = (k: number) => Buffer.from(account(k), 'utf-8').length
  let kmax = 1
  while (bytes(kmax + 1) <= 299) kmax++
  const perTransfer: number[] = []
  let left = pairs - 9
  while (left > 0) {
    let take = Math.min(2 + 2 * kmax, left)
    // Never leave fewer pairs than the smallest transfer has (title, one page each way, amount).
    if (left - take > 0 && left - take < 4) take -= 4 - (left - take)
    if (take < 4) throw new Error(`cannot build a review of ${pairs} pairs`)
    perTransfer.push(take)
    left -= take
  }
  const amount = '1'.repeat(page - 4) // shown as "KDA " and the digits: one full page
  const caps = perTransfer.map(t => {
    const from = Math.ceil((t - 2) / 2)
    return `{"name":"coin.TRANSFER","args":["${account(from)}","${account(t - 2 - from)}",${amount}]}`
  })
  const json = deviceScoped([...caps, '{"name":"free.unverified.CAP","args":[]}'].join(',')).replace(
    '"networkId":"mainnet01"',
    `"networkId":"${'n'.repeat(page)}"`,
  )
  return { json, transfers: perTransfer.length }
}
