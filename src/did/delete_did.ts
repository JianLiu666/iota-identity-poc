import { createDocument, newIdentityClient, newMemStorage } from '../util';

async function deleteIdentity() {
  const storage = newMemStorage();
  const identityClient = await newIdentityClient(storage);
  const [unpublished] = await createDocument(storage);

  // create new identity for this account and publish document for it
  const { output: identity } = await identityClient
    .createIdentity(unpublished)
    .finish()
    .buildAndExecute(identityClient);
  const did = identity.didDocument().id();

  // Resolve the latest state of the document.
  // Technically this is equivalent to the document above.
  const resolved = await identityClient.resolveDid(did);
  console.log('Resolved DID document:', JSON.stringify(resolved, null, 2));

  const controllerToken = await identity.getControllerToken(identityClient);

  // delete the DID.
  await identity
    .deleteDid(controllerToken!)
    .withGasBudget(BigInt(50_000_000))
    .buildAndExecute(identityClient);

  // After an Identity's DID has been deleted, the document will be
  // empty and inactive. Identity.hasDeletedDid must return `true`.
  const is_deleted = identity.didDocument().metadata().deactivated() && identity.hasDeletedDid();
  if (!is_deleted) {
    throw new Error('failed to delete DID Document');
  }

  // Resolving a deleted DID must throw an error.
  try {
    let deactivated = await identityClient.resolveDid(did);
  } catch (_) {
    console.log(`DID ${did} was successfully deleted!`);
  }

  // Trying to update a deleted DID must fail!
  try {
    await identity
      .updateDidDocument(resolved, controllerToken!)
      .withGasBudget(BigInt(50_000_000))
      .buildAndExecute(identityClient);
  } catch (_) {
    console.log('A deleted DID cannot be updated!');
  }
}

deleteIdentity().catch((error) => {
  console.error('Example error:', error);
});
