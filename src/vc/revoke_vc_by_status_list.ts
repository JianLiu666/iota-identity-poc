import { IotaClient } from '@iota/iota-sdk/client';
import { createDocumentForNetwork, newIdentityClient, newMemStorage, NETWORK_URL } from '../util';
import {
  Credential,
  EdDSAJwsVerifier,
  FailFast,
  JwsSignatureOptions,
  JwtCredentialValidationOptions,
  JwtCredentialValidator,
  StatusCheck,
  StatusList2021,
  StatusList2021Credential,
  StatusList2021CredentialBuilder,
  StatusList2021Entry,
  StatusPurpose,
} from '@iota/identity-wasm/node';

async function revokeVCByStatusList() {
  // ===========================================================================
  // Create a Verifiable Credential.
  // ===========================================================================

  // create new client to connect to IOTA network
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
  const issuerDocument = issuerIdentity.didDocument();
  const resolvedIssuer = await issuerClient.resolveDid(issuerDocument.id());
  console.log(`Resolved Issuer document: ${JSON.stringify(resolvedIssuer, null, 2)}`);

  // Create an identity for the holder, and publish DID document for it, in this case also the subject.
  const aliceStorage = newMemStorage();
  const aliceClient = await newIdentityClient(aliceStorage);
  const [unpublishedAliceDocument] = await createDocumentForNetwork(aliceStorage, network);
  const { output: aliceIdentity } = await aliceClient
    .createIdentity(unpublishedAliceDocument)
    .finish()
    .buildAndExecute(aliceClient);
  const aliceDocument = aliceIdentity.didDocument();
  const resolvedAlice = await aliceClient.resolveDid(aliceDocument.id());
  console.log(`Resolved Alice document: ${JSON.stringify(resolvedAlice, null, 2)}`);

  // Create a new empty status list. No credentials have been revoked yet.
  // const statusList = new StatusList2021();

  // Create a status list credential so that the status list can be stored anywhere.
  // The issuer makes this credential available on `http://example.com/credential/status`.
  // For the purposes of this example, the credential will be used directly without fetching.
  const statusListCredential = new StatusList2021CredentialBuilder()
    .purpose(StatusPurpose.Revocation)
    .subjectId('http://localhost:8787/status')
    .issuer(issuerDocument.id().toString())
    .build();
  const statusListCredentialJSON = statusListCredential.toJSON();
  console.log('Status list credential > ' + statusListCredential);

  // send status list to local server
  const STATUS_LIST_URL = 'http://localhost:8787/status';
  await fetch(STATUS_LIST_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(statusListCredentialJSON),
  });

  // Create a credential subject indicating the degree earned by Alice, linked to their DID.
  const subject = {
    id: aliceDocument.id(),
    name: 'Alice',
    degreeName: 'Bachelor of Science and Arts',
    degreeType: 'BachelorDegree',
    GPA: '4.0',
  };

  // Create an unsigned `UniversityDegree` credential for Alice.
  // The issuer also chooses a unique `StatusList2021` index to be able to revoke it later.
  const CREDENTIAL_INDEX = 5;
  const status = new StatusList2021Entry(
    statusListCredential.id(),
    statusListCredential.purpose(),
    CREDENTIAL_INDEX,
  ).toStatus();
  const credential = new Credential({
    id: 'https://example.edu/credentials/3732',
    type: 'UniversityDegreeCredential',
    issuer: issuerDocument.id(),
    credentialSubject: subject,
    credentialStatus: status,
  });

  // Create signed JWT credential.
  const credentialJwt = await issuerDocument.createCredentialJwt(
    issuerStorage,
    issuerFragment,
    credential,
    new JwsSignatureOptions(),
  );
  console.log(`Credential JWT > ${credentialJwt.toString()}`);

  // Validate the credential using the issuer's DID Document.
  const validationOptions = new JwtCredentialValidationOptions({
    // Built-in status check only supports RevocationBitmap; skip unsupported
    status: StatusCheck.SkipUnsupported,
  });

  // Fetch the StatusList from the local server and validate against it.
  let jwtCredentialValidator = new JwtCredentialValidator(new EdDSAJwsVerifier());
  try {
    jwtCredentialValidator.validate(
      credentialJwt,
      issuerDocument,
      validationOptions,
      FailFast.FirstError,
    );

    // Check status using the fetched StatusList (should pass: not revoked yet)
    const fetchedSLCJson = await fetch(STATUS_LIST_URL).then((r) => {
      if (!r.ok) throw new Error(`Failed to fetch StatusList: ${r.status}`);
      return r.json();
    });
    const fetchedSLC = StatusList2021Credential.fromJSON(fetchedSLCJson);
    JwtCredentialValidator.checkStatusWithStatusList2021(
      credential,
      fetchedSLC,
      StatusCheck.Strict,
    );
  } catch (e) {
    // This line shouldn't be called as the credential is valid and unrevoked
    console.log('Something went wrong: ' + e);
  }

  // ===========================================================================
  // Revocation of the Verifiable Credential.
  // ===========================================================================

  // At a later time, the issuer university found out that Alice cheated in her final exam.
  // The issuer will revoke Alice's credential.

  // The issuer retrieves the current status list from the local server.
  const refetchedSLCJson = await fetch(STATUS_LIST_URL).then((r) => {
    if (!r.ok) throw new Error(`Failed to fetch StatusList for update: ${r.status}`);
    return r.json();
  });
  const refetchedStatusListCredential = StatusList2021Credential.fromJSON(refetchedSLCJson);

  // Update the status list credential.
  // This revokes the credential's unique index.
  refetchedStatusListCredential.setCredentialStatus(credential, CREDENTIAL_INDEX, true);

  // Persist the updated list back to the local server.
  await fetch(STATUS_LIST_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(refetchedStatusListCredential.toJSON()),
  });

  // Credential verification now fails (using freshly fetched list).
  try {
    jwtCredentialValidator.validate(
      credentialJwt,
      issuerDocument,
      validationOptions,
      FailFast.FirstError,
    );

    /// Since the credential has been revoked, this validation step will throw an error.
    const afterUpdateSLCJson = await fetch(STATUS_LIST_URL).then((r) => {
      if (!r.ok) throw new Error(`Failed to fetch StatusList after update: ${r.status}`);
      return r.json();
    });
    const afterUpdateSLC = StatusList2021Credential.fromJSON(afterUpdateSLCJson);
    JwtCredentialValidator.checkStatusWithStatusList2021(
      credential,
      afterUpdateSLC,
      StatusCheck.Strict,
    );
    // In case the revocation failed for some reason we will hit this point
    console.log('Revocation Failed!');
  } catch (e) {
    /// The credential has been revoked.
    console.log('The credential has been successfully revoked.');
  }
}

revokeVCByStatusList().catch((error) => {
  console.error('Example error:', error);
});
