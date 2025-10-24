import { TimeLock } from '@iota/notarization/node';
import { newMemStorage, newNotarizationClient } from '../util';
import assert from 'assert';

async function createLocked() {
  console.log('Creating a simple locked notarization example');

  // create a new client that offers notarization related functions
  const storage = newMemStorage();
  const notarizationClient = await newNotarizationClient(storage);

  // Calculate an unlock time (24 hours from now) to be used for deleteLock
  const delete_unlock_at = Math.round(Date.now() / 1000 + 86400); // 24 hours

  // create a new Locked Notarization
  console.log('Building a simple locked notarization and publish it to the IOTA network');

  // Create a locked notarization with state and delete lock - we will not only access the returned OnChainNotarization
  // later on, but also the returned IotaTransactionBlockResponse containing the transaction details.
  const { output: notarization, response: response } = await notarizationClient
    .createLocked()
    .withStringState('Important document content', 'Document metadata e.g., version specifier')
    .withDeleteLock(TimeLock.withUnlockAt(delete_unlock_at))
    .withImmutableDescription('This can not be changed any more')
    .withUpdatableMetadata('This can be updated')
    .finish()
    .buildAndExecute(notarizationClient);

  console.log(`✅ Locked notarization created successfully with TX digest ${response.digest}!`);

  // check some important properties of the received OnChainNotarization
  console.log('\n----------------------------------------------------');
  console.log('----- Important Notarization Properties ------------');
  console.log('----------------------------------------------------');
  console.log('Notarization ID: ', notarization.id);
  console.log('Notarization Method: ', notarization.method);
  console.log(
    `State data as string: "${notarization.state.data.toString()}" or as bytes: [${notarization.state.data.toBytes()}]`,
  );
  console.log('State metadata: ', notarization.state.metadata);
  console.log('Immutable description: ', notarization.immutableMetadata.description);
  console.log('Immutable locking metadata: ', notarization.immutableMetadata.locking);
  console.log('Updatable metadata: ', notarization.updatableMetadata);
  console.log('State version count: ', notarization.stateVersionCount);
  console.log('Owner: ', notarization.owner);
  // This is what the complete OnChainNotarization looks like
  console.log('\n----------------------------------------------------');
  console.log('----- All Notarization Properties      -------------');
  console.log('----------------------------------------------------');
  console.log('Notarization: ', notarization);

  // Verify the notarization method is Locked
  assert(notarization.method === 'Locked');

  // Check if it has locking metadata and `updateLock` + `transferLock` are set to `UntilDestroyed`
  assert(notarization.immutableMetadata.locking !== undefined);
  assert(notarization.immutableMetadata.locking.updateLock.type === 'UntilDestroyed');
  assert(notarization.immutableMetadata.locking.transferLock.type === 'UntilDestroyed');

  console.log(
    '\n🔒 The notarization is Locked and cannot be updated or transferred until it is destroyed',
  );
  console.log('🗑️  The notarization can only be destroyed after the delete lock expires');
}

createLocked().catch((error) => {
  console.error('Example error:', error);
});
