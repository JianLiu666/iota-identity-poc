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
  MethodDigest,
  Storage,
  StorageSigner,
  JwkUse,
  EdCurve,
  JwkOperation,
  VerificationMethod,
  IotaDID,
} from '@iota/identity-wasm/node';
import { getNetwork, IotaClient, Network } from '@iota/iota-sdk/client';
import { getFaucetHost, requestIotaFromFaucetV0 } from '@iota/iota-sdk/faucet';
import { NotarizationClient, NotarizationClientReadOnly } from '@iota/notarization/node';
import { Ed25519Keypair } from '@iota/iota-sdk/keypairs/ed25519';
import { decodeIotaPrivateKey } from '@iota/iota-sdk/cryptography';
import { createHash } from 'crypto';

export const NETWORK = Network.Testnet;
export const NETWORK_URL = getNetwork(NETWORK).url;
export const ONE_IOTA = 1_000_000_000n; // base units

export async function requestFunds(address: string) {
  await requestIotaFromFaucetV0({
    host: getFaucetHost(NETWORK),
    recipient: address,
  });
}

export function newMemStorage(): Storage {
  return new Storage(new JwkMemStore(), new KeyIdMemStore());
}

export function newSecretKey(): string {
  const iotaPrivateKey = Ed25519Keypair.generate().getSecretKey();
  const secretKeyUint8Array = decodeIotaPrivateKey(iotaPrivateKey).secretKey;
  const secretKeyBase64url = Buffer.from(secretKeyUint8Array).toString('base64url');
  return secretKeyBase64url;
}

export async function createDocument(storage: Storage): Promise<[IotaDocument, string]> {
  const unpublished = new IotaDocument(NETWORK);
  const verificationMethodFragment = await unpublished.generateMethod(
    storage,
    JwkMemStore.ed25519KeyType(),
    JwsAlgorithm.EdDSA,
    '#key-1',
    MethodScope.VerificationMethod(),
  );

  return [unpublished, verificationMethodFragment];
}

export async function createDocumentWithKey(
  storage: Storage,
  base64SecretKey: string,
  fragment: string = '#key-1',
): Promise<[IotaDocument, string]> {
  const unpublished = new IotaDocument(NETWORK);

  // Build a JWK from the provided secret key and insert it into storage to obtain keyId.
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

  // Create a verification method from the public JWK and insert it into the document.
  const method = VerificationMethod.newFromJwk(unpublished.id(), publicKeyJwk, fragment);
  unpublished.insertMethod(method, MethodScope.VerificationMethod());

  // Map the inserted verification method to the keyId in KeyIdMemStore so it can be used for createJws.
  const methodDigest = new MethodDigest(method);
  await storage.keyIdStorage().insertKeyId(methodDigest, keyId);

  return [unpublished, method.id().fragment()!];
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

export async function newIdentityClientFromSecretKey(
  base64SecretKey: string,
  checkBalance: boolean = false,
): Promise<[IdentityClient, Storage, string]> {
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
  if (checkBalance && current < ONE_IOTA) {
    await requestFunds(identityClient.senderAddress());
    bal = await iotaClient.getBalance({ owner: identityClient.senderAddress() });
    current = BigInt(bal.totalBalance);
    if (current < ONE_IOTA) {
      throw new Error('Balance is still below 1 IOTA after faucet');
    }
  }
  console.log(`Current balance: ${current.toString()} for owner ${identityClient.senderAddress()}`);

  return [identityClient, storage, keyId];
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

export async function newNotarizationClientFromSecretKey(
  base64SecretKey: string,
  checkBalance: boolean = false,
): Promise<NotarizationClient> {
  const iotaClient = new IotaClient({ url: NETWORK_URL });
  const notarizationClientReadOnly = await NotarizationClientReadOnly.create(iotaClient);

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

  // create signer
  let signer = new StorageSigner(storage, keyId, publicKeyJwk);
  const notarizationClient = await NotarizationClient.create(notarizationClientReadOnly, signer);

  let bal = await iotaClient.getBalance({ owner: notarizationClient.senderAddress() });
  let current = BigInt(bal.totalBalance);
  if (checkBalance && current < ONE_IOTA) {
    await requestFunds(notarizationClient.senderAddress());
    bal = await iotaClient.getBalance({ owner: notarizationClient.senderAddress() });
    current = BigInt(bal.totalBalance);
    if (current < ONE_IOTA) {
      throw new Error('Balance is still below 1 IOTA after faucet');
    }
  }
  console.log(
    `Current balance: ${current.toString()} for owner ${notarizationClient.senderAddress()}`,
  );

  return notarizationClient;
}

export async function getIdentity(
  base64SecretKey: string,
  did: string,
): Promise<[IdentityClient, Storage, IotaDocument, string]> {
  const [client, storage, keyId] = await newIdentityClientFromSecretKey(base64SecretKey, false);
  const document = await client.resolveDid(IotaDID.parse(did));

  const method = document.methods()[0];
  const methodFragment = method.id().fragment()!;
  const methodDigest = new MethodDigest(method);
  await storage.keyIdStorage().insertKeyId(methodDigest, keyId);

  return [client, storage, document, methodFragment];
}

function getEd25519KeypairFromBase64SecretKey(base64SecretKey: string): Ed25519Keypair {
  const uint8Array = Uint8Array.from(Buffer.from(base64SecretKey, 'base64url'));
  return Ed25519Keypair.fromSecretKey(uint8Array);
}

function decodeIotaPrivateKeyToBase64Url(iotaPrivateKey: string) {
  const secretKeyUint8Array = decodeIotaPrivateKey(iotaPrivateKey).secretKey;
  const secretKeyBase64url = Buffer.from(secretKeyUint8Array).toString('base64url');
  console.log(secretKeyBase64url);
}

function showIotaPrivateKeyFromBase64SecretKey(base64SecretKey: string) {
  const iotaPrivateKey = getEd25519KeypairFromBase64SecretKey(base64SecretKey).getSecretKey();
  console.log(iotaPrivateKey);
}

function showJwkFromBase64SecretKey(base64SecretKey: string) {
  const keypair = getEd25519KeypairFromBase64SecretKey(base64SecretKey);
  const { secretKey } = decodeIotaPrivateKey(keypair.getSecretKey());
  const publicKey = keypair.getPublicKey().toRawBytes();

  const hash = createHash('sha256').update(Buffer.from(publicKey)).digest();
  const kid = hash.toString('base64url');

  const jwk = new Jwk({
    use: JwkUse.Signature,
    kty: JwkType.Okp,
    kid: kid,
    crv: EdCurve.Ed25519,
    alg: JwsAlgorithm.EdDSA,
    x: Buffer.from(publicKey).toString('base64url'),
    d: Buffer.from(secretKey).toString('base64url'),
  });
  console.log(JSON.stringify(jwk, null, 2));
}
