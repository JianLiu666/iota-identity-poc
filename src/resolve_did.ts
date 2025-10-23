import { IotaClient } from '@iota/iota-sdk/client';
import { createDocumentForNetwork, getFundedClient, getMemStorage, NETWORK_URL } from './util';
import { CoreDocument, DIDJwk, IToCoreDocument, Resolver } from '@iota/identity-wasm/node';

const DID: string =
  'did:iota:testnet:0xbf8b466d396802791cf5866baaba5de1c749507205a575df58ce358c5f5a7e45';

async function resolveIdentity() {
  // create new clients and create new account
  const iotaClient = new IotaClient({ url: NETWORK_URL });
  const network = await iotaClient.getChainIdentifier();
  const storage = getMemStorage();
  const identityClient = await getFundedClient(storage);
  const [unpublished] = await createDocumentForNetwork(storage, network);

  // create new identity for this account and publish document for it
  const { output: identity } = await identityClient
    .createIdentity(unpublished)
    .finish()
    .buildAndExecute(identityClient);
  const did = identity.didDocument().id();

  // Resolve the associated identity and extract the DID document from it.
  const resolved = await identityClient.resolveDid(did);
  console.log('Resolved DID document:', JSON.stringify(resolved, null, 2));

  // We can resolve the Object ID directly
  const resolvedIdentity = await identityClient.getIdentity(identity.id());
  console.dir(resolvedIdentity);
  console.log(
    `Identity client resolved identity has object ID ${resolvedIdentity.toFullFledged()?.id()}`,
  );
}

resolveIdentity().catch((error) => {
  console.error('Example error:', error);
});
