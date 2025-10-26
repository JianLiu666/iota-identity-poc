import { IotaClient } from '@iota/iota-sdk/client';
import {
  NotarizationClient,
  NotarizationClientReadOnly,
  OnChainNotarization,
} from '@iota/notarization/node';
import { createDocument, newIdentityClient, newMemStorage, NETWORK_URL } from '../util';
import {
  CoreDID,
  Credential,
  EdDSAJwsVerifier,
  IdentityClientReadOnly,
  IotaDocument,
  IrlResolver,
  JwsSignatureOptions,
  Jwt,
  JwtPresentationOptions,
  JwtPresentationValidationOptions,
  JwtPresentationValidator,
  LinkedVerifiablePresentationService,
  Presentation,
  Resolver,
  Storage,
  TransactionSigner,
} from '@iota/identity-wasm/node';

async function linkedVp() {
  // ===========================================================================
  // Create identities and clients.
  // ===========================================================================

  // Create new client to connect to IOTA network
  const iotaClient = new IotaClient({ url: NETWORK_URL });
  const network = await iotaClient.getChainIdentifier();

  // Create issuer account, create identity, and publish DID document for it
  const storage = newMemStorage();
  const identityClient = await newIdentityClient(storage);
  const notarizationClient = await newNotarizationClient(identityClient.signer());
  const [unpublishedDidDocument, fragment] = await createDocument(storage);
  const publishedDidDocument = await identityClient
    .publishDidDocument(unpublishedDidDocument, identityClient.senderAddress())
    .buildAndExecute(identityClient)
    .then((res) => res.output);
  const resolvedDidDocument = await identityClient.resolveDid(publishedDidDocument.id());
  console.log(`Resolved did document: ${JSON.stringify(resolvedDidDocument, null, 2)}`);

  // ===========================================================================
  // Create a Verifiable Presentation and host it on-chain.
  // ===========================================================================

  const jwtVp = await makeVpJwt(publishedDidDocument, storage, fragment);
  const notarizedVp: OnChainNotarization = await notarizationClient
    .createLocked()
    .withStringState(jwtVp.toString(), 'My Linked VP')
    .finish()
    .buildAndExecute(notarizationClient)
    .then((res) => res.output);
  console.log(`Notarized VP: ${notarizedVp.toString()}`);

  // ===========================================================================
  // Create Linked Verifiable Presentation service.
  // ===========================================================================

  const serviceUrl = publishedDidDocument.id().join('#linked-vp');
  const linkedVpService = new LinkedVerifiablePresentationService({
    id: serviceUrl,
    linkedVp: notarizedVp.iotaResourceLocatorBuilder(notarizationClient.network()).data(),
  });
  publishedDidDocument.insertService(linkedVpService.toService());

  await identityClient.publishDidDocumentUpdate(publishedDidDocument, BigInt(50_000_000));

  // ===========================================================================
  // Verification.
  // ===========================================================================

  const resolver = new Resolver<IotaDocument>({
    client: await IdentityClientReadOnly.create(iotaClient),
  });
  // Resolve the presentation holder.
  const presentationHolderDID: CoreDID = JwtPresentationValidator.extractHolder(jwtVp);
  const resolvedHolder = await resolver.resolve(presentationHolderDID.toString());

  // Get the Linked Verifiable Presentation Services from the DID Document.
  const linkedVpServices = resolvedHolder
    .service()
    .filter((service) => service.type().includes('LinkedVerifiablePresentation'));
  console.assert(
    linkedVpServices.length == 1,
    'expected exactly one Linked Verifiable Presentation service',
  );

  // Get the VPs included the service.
  const vpUrl = LinkedVerifiablePresentationService.fromService(
    linkedVpServices[0],
  ).verifiablePresentationUrls()[0];
  console.log(`Fetching VP at \`${vpUrl}\``);

  const irlResolver = new IrlResolver({
    customNetworks: [{ chainId: network, endpoint: NETWORK_URL }],
  });
  const resolvedJwtVp = await irlResolver.resolve(vpUrl).then((value) => new Jwt(value as string));

  // Validate presentation. Note that this doesn't validate the included credentials.
  const _decodedPresentation = new JwtPresentationValidator(new EdDSAJwsVerifier()).validate(
    resolvedJwtVp,
    resolvedHolder,
    new JwtPresentationValidationOptions(),
  );

  console.log('Successfully validated the fetched presentation');
}

async function makeVpJwt(
  didDocument: IotaDocument,
  storage: Storage,
  fragment: string,
): Promise<Jwt> {
  const credential = new Credential({
    id: 'https://example.edu/credentials/3732',
    type: 'UniversityDegreeCredential',
    issuer: didDocument.id(),
    credentialSubject: {
      id: didDocument.id(),
      name: 'Alice',
      degreeName: 'Bachelor of Science and Arts',
      degreeType: 'BachelorDegree',
      GPA: '4.0',
    },
  });
  const jwtCredential = await didDocument.createCredentialJwt(
    storage,
    fragment,
    credential,
    new JwsSignatureOptions(),
  );

  const presentation = new Presentation({
    holder: didDocument.id(),
    verifiableCredential: [jwtCredential],
  });
  const jwtVp = await didDocument.createPresentationJwt(
    storage,
    fragment,
    presentation,
    new JwsSignatureOptions(),
    new JwtPresentationOptions(),
  );

  return jwtVp;
}
async function newNotarizationClient(signer: TransactionSigner): Promise<NotarizationClient> {
  const iotaClient = new IotaClient({ url: NETWORK_URL });
  const notarizationClientReadOnly = await NotarizationClientReadOnly.create(iotaClient);

  return await NotarizationClient.create(notarizationClientReadOnly, signer);
}

linkedVp().catch((error) => {
  console.error('Example error:', error);
});
