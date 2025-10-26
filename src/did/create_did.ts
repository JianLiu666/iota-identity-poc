import { newIdentityClient, newMemStorage, createDocument } from '../util';
import { IotaDID } from '@iota/identity-wasm/node';

async function createIdentity(): Promise<void> {
  // create new client that offers identity related functions
  const storage = newMemStorage();
  const identityClient = await newIdentityClient(storage);

  // create new unpublished document
  const [unpublished] = await createDocument(storage);
  console.log(`Unpublished DID document: ${JSON.stringify(unpublished, null, 2)}`);

  let did: IotaDID;
  console.log('Creating new identity');
  const { output: identity } = await identityClient
    .createIdentity(unpublished)
    .finish()
    .buildAndExecute(identityClient);
  did = identity.didDocument().id();

  // check if we can resolve it via client
  const resolved = await identityClient.resolveDid(did);
  console.log(`Resolved DID document: ${JSON.stringify(resolved, null, 2)}`);
}

createIdentity().catch((error) => {
  console.error('Example error:', error);
});
