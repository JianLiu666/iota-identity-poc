import {
  IdentityClient,
  IdentityClientReadOnly,
  IotaDocument,
  JwkMemStore,
  JwsAlgorithm,
  KeyIdMemStore,
  MethodScope,
  Storage,
  StorageSigner,
} from '@iota/identity-wasm/node';
import { IotaClient, Network } from '@iota/iota-sdk/client';
import { getFaucetHost, requestIotaFromFaucetV0 } from '@iota/iota-sdk/faucet';
import { NotarizationClient, NotarizationClientReadOnly } from '@iota/notarization/node';

export const NETWORK_URL = 'https://api.testnet.iota.cafe';

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
  let generate = await storage.keyStorage().generate('Ed25519', JwsAlgorithm.EdDSA);

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

export async function newNotarizationClient(storage: Storage): Promise<NotarizationClient> {
  const iotaClient = new IotaClient({ url: NETWORK_URL });

  const notarizationClientReadOnly = await NotarizationClientReadOnly.create(iotaClient);

  // generate new key
  let generate = await storage.keyStorage().generate('Ed25519', JwsAlgorithm.EdDSA);

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
