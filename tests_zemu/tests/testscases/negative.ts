import { PATH } from '../common'

// Security-regression payloads (F15). Each exercises a fixed memory-safety / display-integrity
// defect and must FAIL CLOSED (the app rejects with an error status word) or render faithfully —
// never crash (a crash surfaces as the Speculos event port dropping in Zemu). Kept as raw JSON so
// the malicious shapes are explicit and self-contained.

const FROM = '83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790'
const TO = '9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42'

const CODE = `(coin.transfer \\"${FROM}\\" \\"${TO}\\" 11.0)`

// A clist of 96 coin.TRANSFER entries each with the WRONG arg count (2, not 3) so every one takes
// the else-branch at items.c:409 that (pre-fix) called items_storeUnknownItem and swallowed its
// items_too_many_items return — driving numOfItems to MAX_NUMBER_OF_ITEMS (100) and a one-past-end
// write over the toString[] function pointers that parser_getItem invokes pre-approval. Wrong-arg
// transfers (not plain unknown caps) guarantee the MAX boundary is hit ON the fixed else-branch.
// Short args ("a","b") keep the token count (~7/entry, ~700 total) under MAX_NUMBER_OF_TOKENS (768
// on nanos2/stax/flex/apex_p) so tokenization does NOT reject first — the item MAX is what's reached.
// On nanox (110-token cap) the token limit gates first, which is itself a valid fail-closed outcome.
// Post-fix the parse must abort cleanly (error SW), never crash.
function manyCapsClist(): string {
  const caps: string[] = ['{"args":[],"name":"coin.GAS"}']
  for (let i = 0; i < 96; i++) caps.push(`{"args":["a","b"],"name":"coin.TRANSFER"}`)
  return caps.join(',')
}

// Same MAX-boundary attack via the ROTATE else-branch (items.c:472): coin.ROTATE with the wrong arg
// count (2, not 1) takes its else-branch. Covers the third swallowed site.
function manyRotateClist(): string {
  const caps: string[] = ['{"args":[],"name":"coin.GAS"}']
  for (let i = 0; i < 96; i++) caps.push(`{"args":["a","b"],"name":"coin.ROTATE"}`)
  return caps.join(',')
}

// gasLimit as a >255-char numeric string: pre-fix the uint8_t length wrapped mod 256 and only a few
// digits were shown while the full value was signed (displayed != signed). Post-fix it must reject.
const BIG_GAS = '1' + '0'.repeat(300)

export const NEGATIVE_SIGN_CASES = [
  {
    name: 'oob_max_items_transfer',
    // Wrong-arg coin.TRANSFER else-branch (items.c:409) at the MAX boundary. Must fail closed.
    json: `{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"${CODE}"}},"signers":[{"pubKey":"${FROM}","clist":[${manyCapsClist()}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"${FROM}"},"nonce":"nonce"}`,
    expectReject: true,
  },
  {
    name: 'oob_max_items_rotate',
    // Wrong-arg coin.ROTATE else-branch (items.c:472) at the MAX boundary. Must fail closed.
    json: `{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"${CODE}"}},"signers":[{"pubKey":"${FROM}","clist":[${manyRotateClist()}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"${FROM}"},"nonce":"nonce"}`,
    expectReject: true,
  },
  {
    name: 'gas_len_wrap',
    // Oversized gas value: must reject (items_data_too_large) rather than mis-display.
    json: `{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"${CODE}"}},"signers":[{"pubKey":"${FROM}","clist":[{"args":[],"name":"coin.GAS"}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":"${BIG_GAS}","chainId":"0","gasPrice":1.0e-5,"sender":"${FROM}"},"nonce":"nonce"}`,
    expectReject: true,
  },
]

// Unknown capability with a short string arg: pre-fix the %s render over-read past the token into
// following JSON (displayed != signed). Post-fix it renders faithfully and the tx signs — this is a
// POSITIVE case whose snapshot pins the corrected on-screen arg rendering.
export const UNKNOWN_CAP_RENDER_CASE = {
  name: 'unknown_cap_arg_render',
  json: `{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"${CODE}"}},"signers":[{"pubKey":"${FROM}","clist":[{"args":[],"name":"coin.GAS"},{"args":["AB"],"name":"foo.BAR"}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"${FROM}"},"nonce":"nonce"}`,
  path: PATH,
}
