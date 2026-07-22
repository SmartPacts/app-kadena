import { PATH } from '../common'

export const APDU_TEST_CASES = [
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
