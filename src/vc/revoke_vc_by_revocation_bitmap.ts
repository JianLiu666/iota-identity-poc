import { IotaClient } from '@iota/iota-sdk/client';
import { createDocumentForNetwork, newIdentityClient, newMemStorage, NETWORK_URL } from '../util';
import {
  Credential,
  EdDSAJwsVerifier,
  FailFast,
  IdentityClientReadOnly,
  IotaDocument,
  JwsSignatureOptions,
  JwtCredentialValidationOptions,
  JwtCredentialValidator,
  Resolver,
  RevocationBitmap,
  Service,
  VerificationMethod,
} from '@iota/identity-wasm/node';

async function revokeVCByRevocationBitmap() {
  // ===========================================================================
  // Create a Verifiable Credential.
  // ===========================================================================

  // Create new client to connect to IOTA network.
  const iotaClient = new IotaClient({ url: NETWORK_URL });
  const network = await iotaClient.getChainIdentifier();

  // Create an identity for the issuer with one verification method `key-1`, and publish DID document for it.
  const issuerStorage = newMemStorage();
  const issuerClient = await newIdentityClient(issuerStorage);
  const [unpublishedIssuerDocument, issuerFragment] = await createDocumentForNetwork(
    issuerStorage,
    network,
  );
  const { output: issuerIdentity } = await issuerClient
    .createIdentity(unpublishedIssuerDocument)
    .finish()
    .buildAndExecute(issuerClient);
  let issuerDocument = issuerIdentity.didDocument();
  const resolvedIssuer = await issuerClient.resolveDid(issuerDocument.id());
  console.log(`Resolved Issuer document: ${JSON.stringify(resolvedIssuer, null, 2)}`);

  // create holder account, create identity, and publish DID document for it.
  const aliceStorage = newMemStorage();
  const aliceClient = await newIdentityClient(aliceStorage);
  const [unpublishedAliceDocument, aliceFragment] = await createDocumentForNetwork(
    aliceStorage,
    network,
  );
  const { output: aliceIdentity } = await aliceClient
    .createIdentity(unpublishedAliceDocument)
    .finish()
    .buildAndExecute(aliceClient);
  const aliceDocument = aliceIdentity.didDocument();
  const resolvedAlice = await aliceClient.resolveDid(aliceDocument.id());
  console.log(`Resolved Alice document: ${JSON.stringify(resolvedAlice, null, 2)}`);

  // Create a new empty revocation bitmap. No credential is revoked yet.
  const revocationBitmap = new RevocationBitmap();

  // Add the revocation bitmap to the DID Document of the issuer as a service.
  const serviceId = issuerDocument.id().join('#my-revocation-service');
  const service: Service = revocationBitmap.toService(serviceId);
  issuerDocument.insertService(service);

  const issuerIdentityToken = await issuerIdentity.getControllerToken(issuerClient);

  // Publish the updated document.
  await issuerIdentity
    .updateDidDocument(issuerDocument, issuerIdentityToken!)
    .withGasBudget(BigInt(50_000_000))
    .buildAndExecute(issuerClient);

  // Create a credential subject indicating the degree earned by Alice, linked to their DID.
  const subject = {
    id: aliceDocument.id(),
    name: 'Alice',
    degreeName: 'Bachelor of Science and Arts',
    degreeType: 'BachelorDegree',
    GPA: '4.0',
  };

  // Create an unsigned `UniversityDegree` credential for Alice.
  // The issuer also chooses a unique `RevocationBitmap` index to be able to revoke it later.
  const CREDENTIAL_INDEX = 5;
  const unsignedVc = new Credential({
    id: 'https://example.edu/credentials/3732',
    type: 'UniversityDegreeCredential',
    issuer: issuerDocument.id(),
    credentialSubject: subject,
    credentialStatus: {
      id: issuerDocument.id() + '#my-revocation-service',
      type: RevocationBitmap.type(),
      revocationBitmapIndex: CREDENTIAL_INDEX.toString(),
    },
  });

  // Create signed JWT credential.
  const credentialJwt = await issuerDocument.createCredentialJwt(
    issuerStorage,
    issuerFragment,
    unsignedVc,
    new JwsSignatureOptions(),
  );
  console.log(`Credential JWT > ${credentialJwt.toString()}`);

  // Validate the credential using the issuer's DID Document.
  let jwtCredentialValidator = new JwtCredentialValidator(new EdDSAJwsVerifier());
  jwtCredentialValidator.validate(
    credentialJwt,
    issuerDocument,
    new JwtCredentialValidationOptions(),
    FailFast.FirstError,
  );
  console.log(`VC successfully validated`);

  // ===========================================================================
  // Revocation of the Verifiable Credential.
  // ===========================================================================

  // Update the RevocationBitmap service in the issuer's DID Document.
  // This revokes the credential's unique index.
  issuerDocument.revokeCredentials('my-revocation-service', CREDENTIAL_INDEX);

  // Publish the changes.
  await issuerIdentity
    .updateDidDocument(issuerDocument, issuerIdentityToken!)
    .withGasBudget(BigInt(50_000_000))
    .buildAndExecute(issuerClient)
    .then((result) => {
      console.log('Revocation response:');
      result.response.balanceChanges?.forEach((balanceChange) => {
        console.log(JSON.stringify(balanceChange, null, 2));
      });
    });

  // Credential verification now fails.
  try {
    jwtCredentialValidator.validate(
      credentialJwt,
      issuerDocument,
      new JwtCredentialValidationOptions(),
      FailFast.FirstError,
    );
    console.log('Revocation Failed!');
  } catch (e) {
    console.log(`Error during validation: ${e}`);
  }

  issuerDocument.unrevokeCredentials('my-revocation-service', CREDENTIAL_INDEX);

  // Publish the changes.
  await issuerIdentity
    .updateDidDocument(issuerDocument, issuerIdentityToken!)
    .withGasBudget(BigInt(50_000_000))
    .buildAndExecute(issuerClient)
    .then((result) => {
      console.log('Unrevocation response:');
      result.response.balanceChanges?.forEach((balanceChange) => {
        console.log(JSON.stringify(balanceChange, null, 2));
      });
    });

  // Credential verification now fails.
  try {
    jwtCredentialValidator.validate(
      credentialJwt,
      issuerDocument,
      new JwtCredentialValidationOptions(),
      FailFast.FirstError,
    );
    console.log('Unrevocation Success!');
  } catch (e) {
    console.log(`Error during unrevocation: ${e}`);
  }
}

revokeVCByRevocationBitmap().catch((error) => {
  console.error('Example error:', error);
});
