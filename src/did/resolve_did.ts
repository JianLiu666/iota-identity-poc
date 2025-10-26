import { createDocument, newIdentityClient, newMemStorage } from '../util';

async function resolveIdentity() {
  const storage = newMemStorage();
  const identityClient = await newIdentityClient(storage);
  const [unpublished] = await createDocument(storage);

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
