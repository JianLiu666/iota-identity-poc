import { IotaClient } from '@iota/iota-sdk/client';
import { Transaction } from '@iota/iota-sdk/transactions';
import { Ed25519Keypair } from '@iota/iota-sdk/keypairs/ed25519';
import { NETWORK_URL, requestFunds } from './util';

const TARGET_ADDRESS = '...';
const NUM_ADDRESSES = 1;
const FAUCET_REQUESTS_PER_ADDRESS = 15;

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function fundAddressFromFaucet(address: string): Promise<void> {
  for (let i = 0; i < FAUCET_REQUESTS_PER_ADDRESS; i++) {
    try {
      await requestFunds(address);
      console.log(`  [${address}] faucet request ${i + 1}/${FAUCET_REQUESTS_PER_ADDRESS} ok`);
    } catch (err) {
      console.log(`  [${address}] faucet request ${i + 1} failed: ${(err as Error).message}`);
    }
    await sleep(1000);
  }
}

async function transferAllToTarget(
  client: IotaClient,
  keypair: Ed25519Keypair,
  target: string,
): Promise<void> {
  const sender = keypair.toIotaAddress();

  const coins = await client.getCoins({ owner: sender, coinType: '0x2::iota::IOTA' });
  if (coins.data.length === 0) {
    console.log(`  [${sender}] no coins to transfer`);
    return;
  }

  const tx = new Transaction();
  tx.setGasPayment(
    coins.data.map((c) => ({
      objectId: c.coinObjectId,
      version: c.version,
      digest: c.digest,
    })),
  );
  tx.transferObjects([tx.gas], target);

  const result = await client.signAndExecuteTransaction({
    signer: keypair,
    transaction: tx,
    options: { showBalanceChanges: true },
  });
  await client.waitForTransaction({ digest: result.digest });
  console.log(`  [${sender}] transferred -> ${target} (digest: ${result.digest})`);
}

async function main() {
  const client = new IotaClient({ url: NETWORK_URL });

  // step.1 — create 10 addresses, each requests faucet 5 times
  const keypairs: Ed25519Keypair[] = [];
  for (let i = 0; i < NUM_ADDRESSES; i++) {
    const kp = Ed25519Keypair.generate();
    keypairs.push(kp);
    console.log(`address[${i}] = ${kp.toIotaAddress()} (privKey=${kp.getSecretKey()})`);
  }

  console.log('\n=== step.1: requesting faucet funds ===');
  for (let i = 0; i < keypairs.length; i++) {
    console.log(`address[${i}] ${keypairs[i].toIotaAddress()}`);
    await fundAddressFromFaucet(keypairs[i].toIotaAddress());
  }

  // give the network a moment to finalize faucet transactions
  await sleep(1000);

  // step.2 — transfer all funds from each address to the target address
  console.log('\n=== step.2: transferring all funds to target ===');
  for (let i = 0; i < keypairs.length; i++) {
    console.log(`address[${i}] ${keypairs[i].toIotaAddress()}`);
    try {
      await transferAllToTarget(client, keypairs[i], TARGET_ADDRESS);
    } catch (err) {
      console.log(`  transfer failed: ${(err as Error).message}`);
    }
  }

  const finalBalance = await client.getBalance({ owner: TARGET_ADDRESS });
  console.log(`\ntarget ${TARGET_ADDRESS} balance: ${finalBalance.totalBalance}`);
}

main();
