import { PATH } from '../common'

// The signer entry is the device's own key for PATH (v1.3.1 reviews that entry and refuses a
// transaction whose signers do not include the device key).
export const JSON_TEST_CASES = [
  {
    name: 'simple_transfer',
    json: '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad\\" \\"9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\\" 11.0)"}},"signers":[{"pubKey":"de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad","clist":[{"args":[],"name":"coin.GAS"},{"args":["de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad","9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42",11],"name":"coin.TRANSFER"}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad"},"nonce":"\\"2021-10-12T03:27:53.700Z\\""}',
    path: PATH,
  },
]

// The v1.3.0 fixture, whose only signer entry is not the device key: v1.3.1 refuses it
// ("Device key is not a signer").
export const JSON_TEST_CASES_V130 = [
  {
    name: 'simple_transfer',
    json: '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\\" \\"9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\\" 11.0)"}},"signers":[{"pubKey":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","clist":[{"args":[],"name":"coin.GAS"},{"args":["83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42",11],"name":"coin.TRANSFER"}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"},"nonce":"\\"2021-10-12T03:27:53.700Z\\""}',
    path: PATH,
  },
]
