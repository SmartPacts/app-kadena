import TransportNodeHid from '@ledgerhq/hw-transport-node-hid'
import { KadenaApp } from '@zondax/ledger-kadena'
import { ed25519 } from '@noble/curves/ed25519'
import pkg from 'blakejs'
const { blake2bFinal, blake2bInit, blake2bUpdate } = pkg

async function verifySignature(signature, message, publicKey, computeBlake2b = true) {
  let hash = message
  if (computeBlake2b) {
    const context = blake2bInit(32)
    blake2bUpdate(context, message)
    hash = Buffer.from(blake2bFinal(context))
  }

  const valid = ed25519.verify(signature, hash, publicKey)
  if (valid) {
    console.log('Valid signature')
  } else {
    console.log('Invalid signature')
  }
}

function decodeHash(encodedHash) {
  let base64Hash = encodedHash.replace(/-/g, '+').replace(/_/g, '/')
  while (base64Hash.length % 4) {
    base64Hash += '='
  }
  return Buffer.from(base64Hash, 'base64')
}

async function main() {
  const transport = await TransportNodeHid.default.open()

  const app = new KadenaApp(transport)

  const PATH = "m/44'/626'/0'/0/0"
  //const PATH_TESTNET = "m/44'/1'/0'/0'/0'"
  const get_resp = await app.getAddressAndPubKey(PATH)
  const pubKey = get_resp.pubkey
  console.log(get_resp)
  console.log(pubKey.toString('hex'))

  let resp = await app.deviceInfo()
  console.log('Device Info', resp)
  resp = await app.getVersion()
  console.log('Version', resp)

  // Sign a transaction
  console.log('Signing a transaction')
  const blob =
    '{"networkId":"mainnet01","payload":{"exec":{"data":{"ks":{"pred":"keys-all","keys":["368820f80c324bbc7c2b0610688a7da43e39f91d118732671cd9c7500ff43cca"]}},"code":"(coin.transfer-create \\"alice\\" \\"bob\\" (read-keyset \\"ks\\") 100.1)\\n(coin.transfer \\"bob\\" \\"alice\\" 0.1)"}},"signers":[{"pubKey":"6be2f485a7af75fedb4b7f153a903f7e6000ca4aa501179c91a2450b777bd2a7","clist":[{"args":["alice","bob",100.1],"name":"coin.TRANSFER"},{"args":[],"name":"coin.GAS"}]},{"pubKey":"368820f80c324bbc7c2b0610688a7da43e39f91d118732671cd9c7500ff43cca","clist":[{"args":["bob","alice",0.1],"name":"coin.TRANSFER"}]}],"meta":{"creationTime":1580316382,"ttl":7200,"gasLimit":1200,"chainId":"0","gasPrice":1.0e-5,"sender":"alice"},"nonce":"2020-01-29 16:46:22.916695 UTC"}'
  let messageToSign = Buffer.from(blob)
  console.log(messageToSign.toString())

  let signatureRequest
  let signatureResponse
  try {
    signatureRequest = app.sign(PATH, messageToSign)

    signatureResponse = await signatureRequest
    console.log(signatureResponse.signature.toString('hex'))

    await verifySignature(signatureResponse.signature, messageToSign, pubKey)
  } catch (e) {
    console.log(e)
  }

  // Sign a hash
  console.log('Signing a hash')
  messageToSign = 'ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c'
  console.log(messageToSign.toString())
  try {
    signatureRequest = app.signHash(PATH, messageToSign)

    signatureResponse = await signatureRequest
    console.log(signatureResponse.signature.toString('hex'))

    const rawHash =
      typeof messageToSign == 'string'
        ? messageToSign.length == 64
          ? Buffer.from(messageToSign, 'hex')
          : Buffer.from(messageToSign, 'base64')
        : Buffer.from(messageToSign)

    await verifySignature(signatureResponse.signature, rawHash, pubKey, false)
  } catch (e) {
    console.log(e)
  }

  console.log('Signing a transfer')
  const txParams = {
    path: PATH,
    recipient: '83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790',
    amount: '1.23',
    network: 'testnet04',
    chainId: 0,
    gasPrice: '1.0e-6',
    gasLimit: '2300',
    creationTime: 1665647810,
    ttl: '600',
    nonce: '2022-10-13 07:56:50.893257 UTC',
  }

  try {
    signatureRequest = app.signTransferTx(txParams.path, txParams)
    signatureResponse = await signatureRequest
    const decodedHash = decodeHash(signatureResponse.pact_command.hash)

    console.log(signatureResponse.pact_command.sigs[0].sig.toString('hex'))
    console.log(decodedHash.toString('hex'))

    await verifySignature(signatureResponse.pact_command.sigs[0].sig, decodedHash, pubKey, false)
  } catch (e) {
    console.log(e)
  }
}

;(async () => {
  await main()
})()
