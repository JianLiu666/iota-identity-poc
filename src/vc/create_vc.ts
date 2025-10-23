import { IotaClient } from '@iota/iota-sdk/client';
import { createDocumentForNetwork, getFundedClient, getMemStorage, NETWORK_URL } from '../util';
import {
  JwsSignatureOptions,
  Credential,
  EdDSAJwsVerifier,
  JwtCredentialValidator,
  JwtCredentialValidationOptions,
  FailFast,
} from '@iota/identity-wasm/node';

async function createVC() {
  // create new client to connect to IOTA network
  const iotaClient = new IotaClient({ url: NETWORK_URL });
  const network = await iotaClient.getChainIdentifier();

  // Create an identity for the issuer with one verification method `key-1`, and publish DID document for it.
  const issuerStorage = getMemStorage();
  const issuerClient = await getFundedClient(issuerStorage);
  const [unpublishedIssuerDocument, issuerFragment] = await createDocumentForNetwork(
    issuerStorage,
    network,
  );
  const { output: issuerIdentity } = await issuerClient
    .createIdentity(unpublishedIssuerDocument)
    .finish()
    .buildAndExecute(issuerClient);
  const issuerDocument = issuerIdentity.didDocument();
  const resolvedIssuer = await issuerClient.resolveDid(issuerDocument.id());
  console.log(`Resolved Issuer document: ${JSON.stringify(resolvedIssuer, null, 2)}`);

  // Create an identity for the holder, and publish DID document for it, in this case also the subject.
  const holderStorage = getMemStorage();
  const holderClient = await getFundedClient(holderStorage);
  const [unpublishedHolderDocument] = await createDocumentForNetwork(holderStorage, network);
  const { output: holderIdentity } = await holderClient
    .createIdentity(unpublishedHolderDocument)
    .finish()
    .buildAndExecute(holderClient);
  const holderDocument = holderIdentity.didDocument();
  const resolvedHolder = await holderClient.resolveDid(holderDocument.id());
  console.log(`Resolved Holder document: ${JSON.stringify(resolvedHolder, null, 2)}`);

  // Create a credential subject indicating the degree earned by holder, linked to their DID.
  const subject = {
    id: holderDocument.id(),
    name: 'holder',
    degreeName: 'degree name',
    degreeType: 'degree type',
    GPA: '4.0',
  };

  // Create an unsigned `UniversityDegree` credential for holder
  const unsignedVc = new Credential({
    id: 'https://example.edu/credentials/3732',
    type: 'UniversityDegreeCredential',
    issuer: issuerDocument.id(),
    credentialSubject: subject,
  });

  // Create signed JWT credential.
  const credentialJwt = await issuerDocument.createCredentialJwt(
    issuerStorage,
    issuerFragment,
    unsignedVc,
    new JwsSignatureOptions(),
  );
  console.log(`Credential JWT > ${credentialJwt.toString()}`);

  // Before sending this credential to the holder the issuer wants to validate that some properties
  // of the credential satisfy their expectations.

  // Validate the credential's signature, the credential's semantic structure,
  // check that the issuance date is not in the future and that the expiration date is not in the past.
  // Note that the validation returns an object containing the decoded credential.
  const decoded_credential = new JwtCredentialValidator(new EdDSAJwsVerifier()).validate(
    credentialJwt,
    issuerDocument,
    new JwtCredentialValidationOptions(),
    FailFast.FirstError,
  );

  // Since `validate` did not throw any errors we know that the credential was successfully validated.
  console.log(`VC successfully validated`);

  // The issuer is now sure that the credential they are about to issue satisfies their expectations.
  // Note that the credential is NOT published to the IOTA Tangle. It is sent and stored off-chain.
  console.log(`Issued credential: ${JSON.stringify(decoded_credential.intoCredential(), null, 2)}`);
}

createVC().catch((error) => {
  console.error('Example error:', error);
});
