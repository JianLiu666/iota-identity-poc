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
} from '@iota/identity-wasm/node';

const ISSUER_SECRET_KEY = 'd3gsWPcEkyg2YklJSpAy0tje2vYY9ZU-hrh5Wfai4m8';
const ISSUER_DID =
  'did:iota:testnet:0x98628fa07f9abc09cab6c58f1a64514cf6e995d722054c0be789c7a82e3b92f2';
const HOLDER_SECRET_KEY = 'X1XL9s24-_HzcvuuuwBb5SY7Khlj2rJLbWV6sJsVy4w';
const HOLDER_DID =
  'did:iota:testnet:0xad37a77073d0752cc4a22a670b94547f9a9972c7242bac023e0c356333fc0bc4';

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
  const notarizationClient = await newNotarizationClientFromSecretKey(ISSUER_SECRET_KEY, true);

  const { output: notarization } = await notarizationClient
    .createLocked()
    .withStringState(jwtPart, 'Example VC JWT part')
    .withImmutableDescription('This can not be changed any more')
    .finish()
    .buildAndExecute(notarizationClient);

  console.log('Notarization:');
  console.log(notarization);
}

async function destroyNotarization(notarizationId: string): Promise<void> {
  const notarizationClient = await newNotarizationClientFromSecretKey(ISSUER_SECRET_KEY, true);
  const notarizationClientReadOnly = notarizationClient.readOnly();

  console.log(`Destroying notarization with ID: ${notarizationId}`);

  const isDestroyAllowed = await notarizationClientReadOnly.isDestroyAllowed(notarizationId);
  console.log(`Is Notarization destroy allowed: ${isDestroyAllowed}`);

  await notarizationClient.destroy(notarizationId).buildAndExecute(notarizationClient);
  console.log('Notarization destroyed successfully');
}

async function createIdentity(): Promise<[IotaDocument, string]> {
  const secretKey = generateSecretKey();
  console.log(`Secret key: ${secretKey}`);

  const [client, storage] = await newIdentityClientFromSecretKey(secretKey, true);

  const [unpublishedDocument, fragment] = await createDocumentWithKey(storage, secretKey, '#key-1');
  const { output: identity } = await client
    .createIdentity(unpublishedDocument)
    .finish()
    .buildAndExecute(client);
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
    .withGasBudget(BigInt(50_000_000))
    .buildAndExecute(client);
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
    .withGasBudget(BigInt(50_000_000))
    .buildAndExecute(client);
}

async function getIdentity(
  base64SecretKey: string,
  did: string,
): Promise<[IdentityClient, Storage, IotaDocument, string]> {
  const [client, storage, keyId] = await newIdentityClientFromSecretKey(base64SecretKey, true);
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
