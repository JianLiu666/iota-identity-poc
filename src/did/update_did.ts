import { IotaClient } from '@iota/iota-sdk/client';
import { createDocumentForNetwork, newIdentityClient, newMemStorage, NETWORK_URL } from '../util';
import {
  JwkMemStore,
  JwsAlgorithm,
  MethodRelationship,
  MethodScope,
  Service,
  VerificationMethod,
} from '@iota/identity-wasm/node';

async function updateIdentity() {
  // create new clients and create new account
  const iotaClient = new IotaClient({ url: NETWORK_URL });
  const network = await iotaClient.getChainIdentifier();
  const storage = newMemStorage();
  const identityClient = await newIdentityClient(storage);
  const [unpublished, vmFragment1] = await createDocumentForNetwork(storage, network);

  // create new identity for this account and publish document for it
  const { output: identity } = await identityClient
    .createIdentity(unpublished)
    .finish()
    .buildAndExecute(identityClient);
  const did = identity.didDocument().id();

  // Resolve the latest state of the document.
  const resolved = await identityClient.resolveDid(did);
  console.log(`Resolved DID document before update: ${JSON.stringify(resolved, null, 2)}`);

  // Insert a new Ed25519 verification method in the DID document.
  const vmFragment2 = await resolved.generateMethod(
    storage,
    JwkMemStore.ed25519KeyType(),
    JwsAlgorithm.EdDSA,
    null,
    MethodScope.VerificationMethod(),
  );

  // Attach a new method relationship to the inserted method.
  resolved.attachMethodRelationship(did.join(`#${vmFragment2}`), MethodRelationship.Authentication);

  // Add a new Service.
  const service: Service = new Service({
    id: did.join('#linked-domain'),
    type: 'LinkedDomains',
    serviceEndpoint: 'https://example.com',
  });
  resolved.insertService(service);

  // Remove a verification method.
  let originalMethod = resolved.resolveMethod(vmFragment1) as VerificationMethod;
  await resolved.purgeMethod(storage, originalMethod.id());

  let controllerToken = await identity.getControllerToken(identityClient);

  let maybePendingProposal = await identity
    .updateDidDocument(resolved.clone(), controllerToken!)
    .withGasBudget(BigInt(50_000_000))
    .buildAndExecute(identityClient)
    .then((result) => result.output);

  console.assert(
    maybePendingProposal == null,
    'the proposal should have been executed right away!',
  );

  // and resolve again to make sure we're looking at the onchain information
  const resolvedAgain = await identityClient.resolveDid(did);
  console.log(`Updated DID document result: ${JSON.stringify(resolvedAgain, null, 2)}`);
}

updateIdentity().catch((error) => {
  console.error('Example error:', error);
});
