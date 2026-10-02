import { PATH } from '../common'

// Legacy 0x03 chunk-boundary cases: each JSON is exactly the length in its name, so the payload
// ends just before, at, or just after the 230-byte APDU boundary (217/218 with the two-component
// path m/44'/626'). The signer entry is the device's own key for the path signed (v1.3.1 refuses a
// transaction whose signers do not include the device key), and the lengths are kept by trimming
// fields the device does not read.
export const APDU_TEST_CASES = [
  {
    name: 'test_apdu_legacy_blob_204',
    json: '{"networkId":"m","signers":[{"pubKey":"de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad","clist":[{"args":["1","2",0],"name":"coin.TRANSFER"}]}],"meta":{"ttl":0,"gasLimit":0,"gasPrice":0}}',
    path: PATH,
  },
  {
    name: 'test_apdu_legacy_blob_205',
    json: '{"networkId":"m0","signers":[{"pubKey":"de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad","clist":[{"args":["1","2",0],"name":"coin.TRANSFER"}]}],"meta":{"ttl":0,"gasLimit":0,"gasPrice":0}}',
    path: PATH,
  },
  {
    name: 'test_apdu_legacy_blob_206',
    json: '{"networkId":"m00","signers":[{"pubKey":"de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad","clist":[{"args":["1","2",0],"name":"coin.TRANSFER"}]}],"meta":{"ttl":0,"gasLimit":0,"gasPrice":0}}',
    path: PATH,
  },
  {
    name: 'test_apdu_legacy_blob_217',
    json: '{"networkId":"m0000000000000","signers":[{"pubKey":"19d87ede176e5b6efbb4eb1c91cc1fa9417e38f5205e8fe4e25a7aa0e41b9458","clist":[{"args":["1","2",0],"name":"coin.TRANSFER"}]}],"meta":{"ttl":0,"gasLimit":0,"gasPrice":0}}',
    path: "m/44'/626'",
  },
  {
    name: 'test_apdu_legacy_blob_218',
    json: '{"networkId":"m00000000000000","signers":[{"pubKey":"19d87ede176e5b6efbb4eb1c91cc1fa9417e38f5205e8fe4e25a7aa0e41b9458","clist":[{"args":["1","2",0],"name":"coin.TRANSFER"}]}],"meta":{"ttl":0,"gasLimit":0,"gasPrice":0}}',
    path: "m/44'/626'",
  },
  {
    name: 'test_apdu_legacy_blob_435',
    json: '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":""}},"signers":[{"pubKey":"de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad","clist":[{"args":["1","2",0],"name":"coin.GAS"},{"args":["1","2",11],"name":"coin.TRANSFER"}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad"},"nonce":"xxxx"}',
    path: PATH,
  },
]

// The v1.3.0 fixtures above, whose signer entry is not the device key. v1.3.1 refuses them
// ("Device key is not a signer", bare 0x6984 on the legacy command).
export const APDU_TEST_CASES_V130 = [
  {
    name: 'test_apdu_legacy_blob_204',
    json: '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":""}},"signers":[{"pubKey":"0123","clist":[{"args":["1","2",0],"name":"coin.TRANSFER"}]}],"meta":{"ttl":0,"gasLimit":0,"gasPrice":0},"nonce":""}',
    path: PATH,
  },
  {
    name: 'test_apdu_legacy_blob_205',
    json: '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":""}},"signers":[{"pubKey":"01234","clist":[{"args":["1","2",0],"name":"coin.TRANSFER"}]}],"meta":{"ttl":0,"gasLimit":0,"gasPrice":0},"nonce":""}',
    path: PATH,
  },
  {
    name: 'test_apdu_legacy_blob_206',
    json: '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":""}},"signers":[{"pubKey":"012345","clist":[{"args":["1","2",0],"name":"coin.TRANSFER"}]}],"meta":{"ttl":0,"gasLimit":0,"gasPrice":0},"nonce":""}',
    path: PATH,
  },
  {
    name: 'test_apdu_legacy_blob_217',
    json: '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":""}},"signers":[{"pubKey":"01234567890123456","clist":[{"args":["1","2",0],"name":"coin.TRANSFER"}]}],"meta":{"ttl":0,"gasLimit":0,"gasPrice":0},"nonce":""}',
    path: "m/44'/626'",
  },
  {
    name: 'test_apdu_legacy_blob_218',
    json: '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":""}},"signers":[{"pubKey":"012345678901234567","clist":[{"args":["1","2",0],"name":"coin.TRANSFER"}]}],"meta":{"ttl":0,"gasLimit":0,"gasPrice":0},"nonce":""}',
    path: "m/44'/626'",
  },
  {
    name: 'test_apdu_legacy_blob_435',
    json: '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":""}},"signers":[{"pubKey":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff834","clist":[{"args":["1","2",0],"name":"coin.GAS"},{"args":["1","2",11],"name":"coin.TRANSFER"}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff834"},"nonce":"\\"2021-10-12T03:27:53.700Z\\""}',
    path: PATH,
  },
]
