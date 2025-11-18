import { decodeIotaPrivateKey } from '@iota/iota-sdk/cryptography';
import { Ed25519Keypair } from '@iota/iota-sdk/keypairs/ed25519';
import {
  createDocumentWithKey,
  newIdentityClientFromSecretKey,
  newNotarizationClientFromSecretKey,
} from './util';
import {
  Credential,
  IdentityClient,
  IotaDID,
  IotaDocument,
  JwsSignatureOptions,
  RevocationBitmap,
  SdJwt,
  SdObjectEncoder,
  Service,
  Storage,
  MethodDigest,
  LinkedDomainService,
  DefaultHttpClient as IdentityDefaultHttpClient,
  GasStationParams as IdentityGasStationParams,
} from '@iota/identity-wasm/node';
import {
  DefaultHttpClient as NotarizationDefaultHttpClient,
  GasStationParams as NotarizationGasStationParams,
} from '@iota/notarization/node';

const ISSUER_SECRET_KEY = 'ZRx8WOO5ZazFsRwkMdey1PnNKyATpKQGrAEiA1qYASU';
const ISSUER_DID =
  'did:iota:testnet:0x090a13ca46fedf341503cb4a0e7e45a92c59f519d4658faf5b2a0d3e526e286a';
const HOLDER_SECRET_KEY = '34Qb87rvuRlcqSkjJARdbPIsKmxWgQOYOjpu_5zQlec';
const HOLDER_DID =
  'did:iota:testnet:0x14d4e454b7f55de5e3fd616c61068476417a638752210f0f8b11303b1e705742';

async function poc() {
  console.log('===========================================================================');
  console.log('\tStep 1: Get issuer and holder identities.');
  console.log('===========================================================================');

  // Issuer
  const [issuerClient, issuerStorage, issuerDocument, issuerMethodFragment] = await getIdentity(
    ISSUER_SECRET_KEY,
    ISSUER_DID,
  );
  console.log(`Issuer Document:\n${JSON.stringify(issuerDocument, null, 2)}`);

  // Holder
  const [holderClient, holderStorage, holderDocument, holderMethodFragment] = await getIdentity(
    HOLDER_SECRET_KEY,
    HOLDER_DID,
  );
  console.log(`Holder Document:\n${JSON.stringify(holderDocument, null, 2)}`);

  console.log('===========================================================================');
  console.log('\tStep 2: Create a SD-JWT Verifiable Credential');
  console.log('===========================================================================');

  const subject = {
    id: holderDocument.id(),
    fullName: 'Holder',
    sex: 'male',
    age: '30',
    dob: '1990-01-01',
    documentType: 'identity',
    documentNumber: 'A123456789',
    countryFull: 'Taiwan',
    countryIso2: 'TW',
    placeOfBirth: 'Taipei',
    issueAuthority: 'Taipei',
    issueDate: '2025-10-25',
  };

  // NOTE: make sure the credential index is unique for each credential
  const CREDENTIAL_INDEX = 1;
  const unsignedVc = new Credential({
    id: 'https://example.com/credentials/1',
    type: 'IdentityCredential',
    issuer: issuerDocument.id(),
    credentialSubject: subject,
    credentialStatus: {
      id: issuerDocument.id() + '#' + issuerDocument.service()[0].id().fragment()!,
      type: RevocationBitmap.type(),
      revocationBitmapIndex: CREDENTIAL_INDEX.toString(),
    },
  });

  const payload = unsignedVc.toJwtClaims();
  const encoder = new SdObjectEncoder(payload);
  const disclosures = [
    // encoder.conceal('/vc/credentialSubject/fullName'),
    encoder.conceal('/vc/credentialSubject/sex'),
    encoder.conceal('/vc/credentialSubject/age'),
    encoder.conceal('/vc/credentialSubject/dob'),
    // encoder.conceal('/vc/credentialSubject/documentType'),
    encoder.conceal('/vc/credentialSubject/documentNumber'),
    encoder.conceal('/vc/credentialSubject/countryFull'),
    encoder.conceal('/vc/credentialSubject/countryIso2'),
    encoder.conceal('/vc/credentialSubject/placeOfBirth'),
    encoder.conceal('/vc/credentialSubject/issueAuthority'),
    encoder.conceal('/vc/credentialSubject/issueDate'),
  ];
  encoder.addSdAlgProperty();

  console.log('Claims set with disclosure digests: ');
  console.log(JSON.stringify(encoder.encodeToObject(), null, 2), '\n');

  const encodedPayload = encoder.encodeToString();
  const jws = await issuerDocument.createJws(
    issuerStorage,
    issuerMethodFragment,
    encodedPayload,
    new JwsSignatureOptions(),
  );

  console.log('===========================================================================');
  console.log('\tStep 3: Issuer sends the JWT and the disclosures to the holder.');
  console.log('===========================================================================');

  // One way to send the JWT and the disclosures, is by creating an SD-JWT with all the disclosures.
  const strDisclosures = disclosures.map((disclosure) => disclosure.toEncodedString());
  const sdJwt = new SdJwt(jws.toString(), strDisclosures);
  const jwtPart = sdJwt.jwt();
  const disclosuresPart = '~' + sdJwt.disclosures().join('~') + '~';

  console.log(`SD-JWT:\n${sdJwt.presentation()}`);
  console.log(`JWT:\n${jwtPart}`);
  console.log(`Disclosures:\n${disclosuresPart}`);

  console.log('===========================================================================');
  console.log("\tStep 4: Issuer notarizes the SD-JWT's JWT part on IOTA.");
  console.log('===========================================================================');

  // issuer send vc hash value on-chain with notarization
  const notarizationClient = await newNotarizationClientFromSecretKey(ISSUER_SECRET_KEY, false);

  // const notarizationPromises = Array.from({ length: 80 }, (_, iterationIndex) => {
  //   console.log(`Creating notarization ${iterationIndex + 1} of 100`);
  //   return (
  //     notarizationClient
  //       .createLocked()
  //       .withStringState(`Test state ${Date.now()}`, `Iteration: ${iterationIndex}`)
  //       .withDeleteLock(TimeLock.withUnlockAt(Math.round(Date.now() / 1000 + 3600)))
  //       .withImmutableDescription('This can not be changed any more')
  //       .withUpdatableMetadata('This can be updated')
  //       .finish()
  //       // .withGasBudget(BigInt(2000000000))
  //       .executeWithGasStation(
  //         notarizationClient,
  //         'http://localhost:9527',
  //         new NotarizationDefaultHttpClient(),
  //         new NotarizationGasStationParams().withAuthToken('jian'),
  //       )
  //   );
  // });

  // await Promise.all(notarizationPromises);

  const { output: notarization } = await notarizationClient
    .createLocked()
    .withStringState(jwtPart, 'Example VC JWT part')
    .withImmutableDescription('This can not be changed any more')
    .finish()
    .executeWithGasStation(
      notarizationClient,
      'http://localhost:9527',
      new NotarizationDefaultHttpClient(),
      new NotarizationGasStationParams().withAuthToken('jian'),
    );

  console.log('Notarization:');
  console.log(notarization);
}

async function destroyNotarization(notarizationId: string): Promise<void> {
  const notarizationClient = await newNotarizationClientFromSecretKey(ISSUER_SECRET_KEY, false);
  const notarizationClientReadOnly = notarizationClient.readOnly();

  console.log(`Destroying notarization with ID: ${notarizationId}`);

  const isDestroyAllowed = await notarizationClientReadOnly.isDestroyAllowed(notarizationId);
  console.log(`Is Notarization destroy allowed: ${isDestroyAllowed}`);

  const { response } = await notarizationClient
    .destroy(notarizationId)
    .executeWithGasStation(
      notarizationClient,
      'http://localhost:9527',
      new NotarizationDefaultHttpClient(),
      new NotarizationGasStationParams().withAuthToken('jian'),
    );

  console.log('Notarization destroyed successfully');
  console.log(response);
}

async function createIdentity(): Promise<[IotaDocument, string]> {
  const secretKey = generateSecretKey();
  console.log(`Secret key: ${secretKey}`);

  const [client, storage] = await newIdentityClientFromSecretKey(secretKey, false);

  const [unpublishedDocument, fragment] = await createDocumentWithKey(storage, secretKey, '#key-1');
  const { output: identity } = await client
    .createIdentity(unpublishedDocument)
    .finish()
    .executeWithGasStation(
      client,
      'http://localhost:9527',
      new IdentityDefaultHttpClient(),
      new IdentityGasStationParams().withAuthToken('jian'),
    );

  const document = identity.didDocument();

  await createRevocationBitmapService(client, document, 'revocation-service-1');
  await createLinkedDomainService(client, document);

  const resolved = await client.resolveDid(document.id());
  console.log(`Resolved document: ${JSON.stringify(resolved, null, 2)}`);

  return [document, fragment];
}

function generateSecretKey(): string {
  const iotaPrivateKey = Ed25519Keypair.generate().getSecretKey();
  const secretKeyUint8Array = decodeIotaPrivateKey(iotaPrivateKey).secretKey;
  const secretKeyBase64url = Buffer.from(secretKeyUint8Array).toString('base64url');
  return secretKeyBase64url;
}

async function createRevocationBitmapService(
  client: IdentityClient,
  document: IotaDocument,
  fragment: string,
) {
  const resolvedIdentity = await client.getIdentity(document.id().toString().split(':').pop()!);
  const onChainIdentity = resolvedIdentity.toFullFledged();
  if (!onChainIdentity) {
    throw new Error('On-chain identity not found');
  }

  // Create a new empty revocation bitmap. No credential is revoked yet.
  const revocationBitmap = new RevocationBitmap();

  // Add the revocation bitmap to the DID Document of the issuer as a service.
  const serviceId = document.id().join(`#${fragment}`);
  const service: Service = revocationBitmap.toService(serviceId);
  document.insertService(service);

  const controllerToken = await onChainIdentity.getControllerToken(client);

  // Publish the updated document.
  await onChainIdentity
    .updateDidDocument(document, controllerToken!)
    .executeWithGasStation(
      client,
      'http://localhost:9527',
      new IdentityDefaultHttpClient(),
      new IdentityGasStationParams().withAuthToken('jian'),
    );
}

async function createLinkedDomainService(client: IdentityClient, document: IotaDocument) {
  const resolvedIdentity = await client.getIdentity(document.id().toString().split(':').pop()!);
  const onChainIdentity = resolvedIdentity.toFullFledged();
  if (!onChainIdentity) {
    throw new Error('On-chain identity not found');
  }

  const serviceUrl = document.id().clone().join('#domain_linkage');
  const linkedDomainService: LinkedDomainService = new LinkedDomainService({
    id: serviceUrl,
    domains: ['https://foo.example.com', 'https://bar.example.com'],
  });
  document.insertService(linkedDomainService.toService());

  const controllerToken = await onChainIdentity.getControllerToken(client);

  // Publish the updated document.
  await onChainIdentity
    .updateDidDocument(document, controllerToken!)
    .executeWithGasStation(
      client,
      'http://localhost:9527',
      new IdentityDefaultHttpClient(),
      new IdentityGasStationParams().withAuthToken('jian'),
    );
}

async function getIdentity(
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

poc().catch((error) => {
  console.error('Example error:', error);
});
