import {
  IdentityClient,
  IdentityClientReadOnly,
  IotaDocument,
  Jwk,
  JwkMemStore,
  JwsAlgorithm,
  JwkType,
  KeyIdMemStore,
  MethodScope,
  Storage,
  StorageSigner,
  JwkUse,
  EdCurve,
  JwkOperation,
} from '@iota/identity-wasm/node';
import { IotaClient, Network } from '@iota/iota-sdk/client';
import { getFaucetHost, requestIotaFromFaucetV0 } from '@iota/iota-sdk/faucet';
import { NotarizationClient, NotarizationClientReadOnly } from '@iota/notarization/node';
import { Ed25519Keypair } from '@iota/iota-sdk/keypairs/ed25519';
import { decodeIotaPrivateKey } from '@iota/iota-sdk/cryptography';

export const NETWORK_URL = 'https://api.testnet.iota.cafe';
const ONE_IOTA = 1_000_000_000n; // base units

export function newMemStorage(): Storage {
  return new Storage(new JwkMemStore(), new KeyIdMemStore());
}

export async function createDocumentForNetwork(
  storage: Storage,
  network: string,
): Promise<[IotaDocument, string]> {
  // Create a new DID document with a placeholder DID.
  const unpublished = new IotaDocument(network);
  const verificationMethodFragment = await unpublished.generateMethod(
    storage,
    JwkMemStore.ed25519KeyType(),
    JwsAlgorithm.EdDSA,
    '#key-1',
    MethodScope.VerificationMethod(),
  );

  return [unpublished, verificationMethodFragment];
}

export async function requestFunds(address: string) {
  await requestIotaFromFaucetV0({
    host: getFaucetHost(Network.Testnet),
    recipient: address,
  });
}

export async function newIdentityClient(storage: Storage): Promise<IdentityClient> {
  const iotaClient = new IotaClient({ url: NETWORK_URL });

  const identityClientReadOnly = await IdentityClientReadOnly.create(iotaClient);

  // generate new key
  let generate = await storage.keyStorage().generate(EdCurve.Ed25519, JwsAlgorithm.EdDSA);

  let publicKeyJwk = generate.jwk().toPublic();
  if (typeof publicKeyJwk === 'undefined') {
    throw new Error('failed to derive public key JWK from generated JWK');
  }
  let keyId = generate.keyId();

  // create signer from storage
  let signer = new StorageSigner(storage, keyId, publicKeyJwk);
  const identityClient = await IdentityClient.create(identityClientReadOnly, signer);

  await requestFunds(identityClient.senderAddress());

  const balance = await iotaClient.getBalance({ owner: identityClient.senderAddress() });
  if (balance.totalBalance === '0') {
    throw new Error('Balance is still 0');
  } else {
    console.log(
      `Received gas from faucet: ${balance.totalBalance} for owner ${identityClient.senderAddress()}`,
    );
  }

  return identityClient;
}

export async function getIdentityClient(base64SecretKey: string): Promise<IdentityClient> {
  const iotaClient = new IotaClient({ url: NETWORK_URL });
  const identityClientReadOnly = await IdentityClientReadOnly.create(iotaClient);

  const storage = newMemStorage();

  const keypair = getEd25519KeypairFromBase64SecretKey(base64SecretKey);
  const { secretKey } = decodeIotaPrivateKey(keypair.getSecretKey());
  const publicKey = keypair.getPublicKey().toRawBytes();

  const jwk = new Jwk({
    kty: JwkType.Okp,
    use: JwkUse.Signature,
    key_ops: [JwkOperation.Sign, JwkOperation.Verify],
    crv: EdCurve.Ed25519,
    x: Buffer.from(publicKey).toString('base64url'),
    d: Buffer.from(secretKey).toString('base64url'),
    alg: JwsAlgorithm.EdDSA,
  });

  const keyId = await storage.keyStorage().insert(jwk);
  const publicKeyJwk = jwk.toPublic();
  if (typeof publicKeyJwk === 'undefined') {
    throw new Error('failed to derive public key JWK from inserted JWK');
  }

  const signer = new StorageSigner(storage, keyId, publicKeyJwk);
  const identityClient = await IdentityClient.create(identityClientReadOnly, signer);

  let bal = await iotaClient.getBalance({ owner: identityClient.senderAddress() });
  let current = BigInt(bal.totalBalance);
  if (current < ONE_IOTA) {
    await requestFunds(identityClient.senderAddress());
    bal = await iotaClient.getBalance({ owner: identityClient.senderAddress() });
    current = BigInt(bal.totalBalance);
    if (current < ONE_IOTA) {
      throw new Error('Balance is still below 1 IOTA after faucet');
    }
  }
  console.log(`Current balance: ${current.toString()} for owner ${identityClient.senderAddress()}`);

  return identityClient;
}

export async function newNotarizationClient(storage: Storage): Promise<NotarizationClient> {
  const iotaClient = new IotaClient({ url: NETWORK_URL });

  const notarizationClientReadOnly = await NotarizationClientReadOnly.create(iotaClient);

  // generate new key
  let generate = await storage.keyStorage().generate(EdCurve.Ed25519, JwsAlgorithm.EdDSA);

  let publicKeyJwk = generate.jwk().toPublic();
  if (typeof publicKeyJwk === 'undefined') {
    throw new Error('failed to derive public key JWK from generated JWK');
  }
  let keyId = generate.keyId();

  // create signer
  let signer = new StorageSigner(storage, keyId, publicKeyJwk);
  const notarizationClient = await NotarizationClient.create(notarizationClientReadOnly, signer);

  await requestFunds(notarizationClient.senderAddress());

  const balance = await iotaClient.getBalance({ owner: notarizationClient.senderAddress() });
  if (balance.totalBalance === '0') {
    throw new Error('Balance is still 0');
  } else {
    console.log(
      `Received gas from faucet: ${balance.totalBalance} for owner ${notarizationClient.senderAddress()}`,
    );
  }

  return notarizationClient;
}

function getEd25519KeypairFromBase64SecretKey(base64SecretKey: string): Ed25519Keypair {
  const uint8Array = Uint8Array.from(Buffer.from(base64SecretKey, 'base64url'));
  return Ed25519Keypair.fromSecretKey(uint8Array);
}
