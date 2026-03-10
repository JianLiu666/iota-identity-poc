import crypto from 'crypto';
import bs58 from 'bs58';

// ─── Constants ───────────────────────────────────────────────────────────────

const CREDENTIAL_ISSUER_BASE_URL = 'http://localhost:8080';
const CREDENTIAL_CONFIGURATION_ID = 'UniversityDegreeCredential';

// ─── Types ───────────────────────────────────────────────────────────────────

interface CredentialOffer {
  credential_issuer: string;
  credential_configuration_ids: string[];
  grants: {
    'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
      'pre-authorized_code': string;
    };
  };
}

interface IssuerMetadata {
  credential_issuer: string;
  authorization_servers: string[];
  credential_endpoint: string;
  credential_configurations_supported: Record<
    string,
    {
      format: string;
      credential_definition: { type: string[] };
    }
  >;
}

interface AuthServerMetadata {
  'pre-authorized_grant_anonymous_access_supported': boolean;
  issuer: string;
  token_endpoint: string;
}

interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  c_nonce: string;
  c_nonce_expires_in: number;
}

interface CredentialResponse {
  credential: string;
  c_nonce: string;
  c_nonce_expires_in: number;
}

interface JwtVcIssuerResponse {
  issuer: string;
  jwks: {
    keys: Array<{
      kty: string;
      x: string;
      y: string;
      crv: string;
      alg: string;
    }>;
  };
}

interface HolderKeyPair {
  privateKey: crypto.KeyObject;
  didKey: string;
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  console.log('\n================================================================');
  console.log('======== Pre-requisite: Issuer creates Credential Offer ========');
  console.log('================================================================\n');

  const offer = await createCredentialOffer();
  const credentialIssuer = offer.credential_issuer;
  const configId = offer.credential_configuration_ids[0];
  const preAuthorizedCode =
    offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];

  console.log('\n===============================================================');
  console.log('================= Step 1: Get Issuer Metadata =================');
  console.log('===============================================================\n');

  const issuerMetadata = await getIssuerMetadata(credentialIssuer);
  const credentialConfig = issuerMetadata.credential_configurations_supported[configId];
  if (!credentialConfig) {
    throw new Error(`Configuration "${configId}" not found in issuer metadata`);
  }

  const format = credentialConfig.format;
  const credentialTypes = credentialConfig.credential_definition.type;
  const credentialEndpoint = issuerMetadata.credential_endpoint;
  const authServerUrl = issuerMetadata.authorization_servers[0];

  console.log(`\nExtracted:`);
  console.log(`  format: ${format}`);
  console.log(`  types: ${JSON.stringify(credentialTypes)}`);
  console.log(`  credential_endpoint: ${credentialEndpoint}`);
  console.log(`  auth_server: ${authServerUrl}`);

  console.log('\n================================================================');
  console.log('=============== Step 2: Get Auth Server Metadata ===============');
  console.log('================================================================\n');

  const authMetadata = await getAuthServerMetadata(authServerUrl);
  if (!authMetadata['pre-authorized_grant_anonymous_access_supported']) {
    throw new Error('Pre-authorized grant anonymous access not supported');
  }
  if (authMetadata.issuer !== credentialIssuer) {
    throw new Error(`Issuer mismatch: ${authMetadata.issuer} !== ${credentialIssuer}`);
  }
  const tokenEndpoint = authMetadata.token_endpoint;
  console.log(`\nExtracted:`);
  console.log(`  token_endpoint: ${tokenEndpoint}`);

  console.log('\n================================================================');
  console.log('=================== Step 3: Get Access Token ===================');
  console.log('================================================================\n');

  const tokenResponse = await getAccessToken(tokenEndpoint, preAuthorizedCode);

  console.log('\n================================================================');
  console.log('==================== Step 4: Get Credential ====================');
  console.log('================================================================\n');

  const holderKeys = generateHolderKeyPair();
  console.log(`Holder DID: ${holderKeys.didKey}\n`);

  const proofJwt = createProofJwt(holderKeys, credentialIssuer, tokenResponse.c_nonce);
  console.log(`Proof JWT header: ${JSON.stringify(decodeJwt(proofJwt).header, null, 2)}`);
  console.log(`Proof JWT payload: ${JSON.stringify(decodeJwt(proofJwt).payload, null, 2)}\n`);

  const credentialResponse = await getCredential(
    credentialEndpoint,
    tokenResponse.access_token,
    format,
    credentialTypes,
    proofJwt,
  );

  console.log('\n===============================================================');
  console.log('================ Step 5: Get Issuer Public Key ================');
  console.log('===============================================================\n');

  const issuerJwks = await getIssuerPublicKey(credentialIssuer);

  console.log('\n===============================================================');
  console.log('================== Step 6: Verify Credential ==================');
  console.log('===============================================================\n');

  const issuerKey = issuerJwks.jwks.keys[0];
  const isValid = verifyJwt(credentialResponse.credential, issuerKey);
  console.log(`Credential JWT signature valid: ${isValid}`);

  const decoded = decodeJwt(credentialResponse.credential);
  console.log(`\nCredential header: ${JSON.stringify(decoded.header, null, 2)}`);
  console.log(`\nCredential payload: ${JSON.stringify(decoded.payload, null, 2)}`);

  console.log('\n================================================================');
  console.log('================= Step 7: Create Authz Request =================');
  console.log('================================================================\n');

  const authzRequestUrl = await createAuthzRequest(configId);
  const parsedRequest = parseAuthzRequest(authzRequestUrl);

  console.log(`Authz Request URL: ${authzRequestUrl}`);
  console.log(`\nExtracted Request Params:`);
  console.log(`  client_id: ${parsedRequest.client_id}`);
  console.log(`  nonce: ${parsedRequest.nonce}`);
  console.log(`  response_uri: ${parsedRequest.response_uri}`);

  console.log('\n===============================================================');
  console.log('====================== Step 8: Verify VP ======================');
  console.log('===============================================================\n');

  const vpJwt = createVPJwt(
    holderKeys,
    credentialResponse.credential,
    parsedRequest.client_id,
    parsedRequest.nonce,
  );

  console.log(`Generated VP JWT: ${vpJwt}\n`);
  console.log(`Generated VP JWT header: ${JSON.stringify(decodeJwt(vpJwt).header, null, 2)}\n`);
  console.log(`Generated VP JWT payload: ${JSON.stringify(decodeJwt(vpJwt).payload, null, 2)}\n`);

  const redirectUri = await verifyVP(
    parsedRequest.response_uri,
    vpJwt,
    parsedRequest.presentation_definition,
  );

  console.log('\n===============================================================');
  console.log('================== Step 9: Call Redirect URI ==================');
  console.log('===============================================================\n');

  await callRedirectUri(redirectUri);
}

main().catch((error) => {
  console.error('Error:', error);
});

// ─── Utilities ───────────────────────────────────────────────────────────────

function generateHolderKeyPair(): HolderKeyPair {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

  const jwk = publicKey.export({ format: 'jwk' });
  const x = Buffer.from(jwk.x!, 'base64url');
  const y = Buffer.from(jwk.y!, 'base64url');

  // Compressed public key: prefix (0x02 even / 0x03 odd) + x
  const prefix = y[y.length - 1] % 2 === 0 ? 0x02 : 0x03;
  const compressedKey = Buffer.concat([Buffer.from([prefix]), x]);

  // P-256 multicodec varint (0x1200) + compressed key → base58 → did:key:z...
  const multicodec = Buffer.from([0x80, 0x24]);
  const didKey = 'did:key:z' + bs58.encode(Buffer.concat([multicodec, compressedKey]));

  return { privateKey, didKey };
}

function createProofJwt(holder: HolderKeyPair, audience: string, nonce: string): string {
  const header = {
    typ: 'openid4vci-proof+jwt',
    alg: 'ES256',
    kid: holder.didKey,
  };
  const payload = {
    aud: audience,
    iat: Math.floor(Date.now() / 1000),
    nonce,
  };

  const signingInput =
    Buffer.from(JSON.stringify(header)).toString('base64url') +
    '.' +
    Buffer.from(JSON.stringify(payload)).toString('base64url');

  const signature = crypto
    .createSign('SHA256')
    .update(signingInput)
    .sign({ key: holder.privateKey, dsaEncoding: 'ieee-p1363' });

  return signingInput + '.' + signature.toString('base64url');
}

function createVPJwt(
  holder: HolderKeyPair,
  credentialJwt: string,
  audience: string,
  nonce: string,
): string {
  const header = {
    typ: 'JWT',
    alg: 'ES256',
    kid: holder.didKey,
  };
  const payload = {
    vp: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiablePresentation'],
      verifiableCredential: [credentialJwt],
    },
    aud: audience,
    nonce: nonce,
    iss: holder.didKey,
    iat: Math.floor(Date.now() / 1000),
    sub: holder.didKey,
  };

  const signingInput =
    Buffer.from(JSON.stringify(header)).toString('base64url') +
    '.' +
    Buffer.from(JSON.stringify(payload)).toString('base64url');

  const signature = crypto
    .createSign('SHA256')
    .update(signingInput)
    .sign({ key: holder.privateKey, dsaEncoding: 'ieee-p1363' });

  return signingInput + '.' + signature.toString('base64url');
}

function decodeJwt(jwt: string): {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
} {
  const [h, p] = jwt.split('.');
  return {
    header: JSON.parse(Buffer.from(h, 'base64url').toString()),
    payload: JSON.parse(Buffer.from(p, 'base64url').toString()),
  };
}

function verifyJwt(
  jwt: string,
  issuerJwk: { kty: string; x: string; y: string; crv: string },
): boolean {
  const parts = jwt.split('.');
  const signingInput = parts[0] + '.' + parts[1];
  const signature = Buffer.from(parts[2], 'base64url');

  const publicKey = crypto.createPublicKey({ key: issuerJwk, format: 'jwk' });

  return crypto
    .createVerify('SHA256')
    .update(signingInput)
    .verify({ key: publicKey, dsaEncoding: 'ieee-p1363' }, signature);
}

// ─── Step Functions ──────────────────────────────────────────────────────────

async function createCredentialOffer(): Promise<CredentialOffer> {
  const url = `${CREDENTIAL_ISSUER_BASE_URL}/configurations/${CREDENTIAL_CONFIGURATION_ID}/offer`;
  const res = await fetch(url, {
    method: 'POST',
  });

  if (!res.ok) {
    throw new Error(`POST ${url} failed: ${res.status} ${await res.text()}`);
  }

  // Response is a URI: openid-credential-offer://?credential_offer=<urlencoded JSON>
  const uri = await res.text();
  const encoded = uri.split('credential_offer=')[1];
  const offer: CredentialOffer = JSON.parse(decodeURIComponent(encoded));

  console.log('Credential Offer:');
  console.log(JSON.stringify(offer, null, 2));
  return offer;
}

async function getIssuerMetadata(credentialIssuer: string): Promise<IssuerMetadata> {
  const url = `${credentialIssuer}/.well-known/openid-credential-issuer`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`GET ${url} failed: ${res.status} ${await res.text()}`);
  }

  const metadata: IssuerMetadata = await res.json();

  console.log('Issuer Metadata:');
  console.log(`  credential_issuer: ${metadata.credential_issuer}`);
  console.log(`  authorization_servers: ${JSON.stringify(metadata.authorization_servers)}`);
  console.log(`  credential_endpoint: ${metadata.credential_endpoint}`);
  console.log(
    `  supported configurations: ${Object.keys(metadata.credential_configurations_supported).join(', ')}`,
  );

  return metadata;
}

async function getAuthServerMetadata(authServerUrl: string): Promise<AuthServerMetadata> {
  const url = `${authServerUrl}/.well-known/oauth-authorization-server`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`GET ${url} failed: ${res.status} ${await res.text()}`);
  }

  const metadata: AuthServerMetadata = await res.json();

  console.log('Auth Server Metadata:');
  console.log(`  issuer: ${metadata.issuer}`);
  console.log(`  token_endpoint: ${metadata.token_endpoint}`);
  console.log(
    `  pre-authorized_grant_anonymous_access_supported: ${metadata['pre-authorized_grant_anonymous_access_supported']}`,
  );
  return metadata;
}

async function getAccessToken(
  tokenEndpoint: string,
  preAuthorizedCode: string,
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
    'pre-authorized_code': preAuthorizedCode,
  });

  const res = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  if (!res.ok) {
    throw new Error(`POST ${tokenEndpoint} failed: ${res.status} ${await res.text()}`);
  }

  const token: TokenResponse = await res.json();

  console.log('Token Response:');
  console.log(`  access_token: ${token.access_token.substring(0, 40)}...`);
  console.log(`  token_type: ${token.token_type}`);
  console.log(`  expires_in: ${token.expires_in}`);
  console.log(`  c_nonce: ${token.c_nonce}`);
  console.log(`  c_nonce_expires_in: ${token.c_nonce_expires_in}`);
  return token;
}

async function getCredential(
  credentialEndpoint: string,
  accessToken: string,
  format: string,
  credentialTypes: string[],
  proofJwt: string,
): Promise<CredentialResponse> {
  const body = {
    format,
    credential_definition: { type: credentialTypes },
    proof: { proof_type: 'jwt', jwt: proofJwt },
  };

  const res = await fetch(credentialEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`POST ${credentialEndpoint} failed: ${res.status} ${await res.text()}`);
  }

  const credential: CredentialResponse = await res.json();
  console.log('Credential Response:');
  console.log(`  c_nonce: ${credential.c_nonce}`);
  console.log(`  c_nonce_expires_in: ${credential.c_nonce_expires_in}`);
  console.log(`  credential: ${credential.credential}`);

  return credential;
}

async function getIssuerPublicKey(credentialIssuer: string): Promise<JwtVcIssuerResponse> {
  const url = `${credentialIssuer}/.well-known/jwt-vc-issuer`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`GET ${url} failed: ${res.status} ${await res.text()}`);
  }

  const data: JwtVcIssuerResponse = await res.json();
  console.log('Issuer JWKS:');
  console.log(JSON.stringify(data.jwks, null, 2));

  return data;
}

async function createAuthzRequest(credentialId: string): Promise<string> {
  const url = `${CREDENTIAL_ISSUER_BASE_URL}/request`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ credentialId }),
  });

  if (!res.ok) {
    throw new Error(`POST ${url} failed: ${res.status} ${await res.text()}`);
  }

  const uri = await res.text();
  return uri;
}

function parseAuthzRequest(uri: string): {
  client_id: string;
  nonce: string;
  response_uri: string;
  presentation_definition: any;
} {
  const urlStr = uri.replace('openid4vp://authorize?', 'http://dummy/?');
  const url = new URL(urlStr);

  return {
    client_id: url.searchParams.get('client_id') || '',
    nonce: url.searchParams.get('nonce') || '',
    response_uri: url.searchParams.get('response_uri') || '',
    presentation_definition: JSON.parse(url.searchParams.get('presentation_definition') || '{}'),
  };
}

async function verifyVP(
  responseUri: string,
  vpToken: string,
  presentationDefinition: any,
): Promise<string> {
  const presentationSubmission = {
    id: 'submission-123',
    definition_id: presentationDefinition.id,
    descriptor_map: [
      {
        id: presentationDefinition.input_descriptors[0].id,
        format: 'jwt_vp_json',
        path: '$',
        path_nested: {
          id: presentationDefinition.input_descriptors[0].id,
          format: 'jwt_vc_json',
          path: '$.vp.verifiableCredential[0]',
        },
      },
    ],
  };

  console.log(`Presentation Submission: ${JSON.stringify(presentationSubmission, null, 2)}\n`);

  const body = new URLSearchParams({
    vp_token: vpToken,
    presentation_submission: JSON.stringify(presentationSubmission),
  });

  const res = await fetch(responseUri, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: body.toString(),
  });

  if (!res.ok) {
    throw new Error(`POST ${responseUri} failed: ${res.status} ${await res.text()}`);
  }

  const data = await res.json();
  console.log('VP Verify Response:');
  console.log(JSON.stringify(data, null, 2));

  return data['redirect_uri'];
}

async function callRedirectUri(redirectUri: string): Promise<void> {
  console.log(`Calling redirect URI: ${redirectUri}\n`);

  const res = await fetch(redirectUri);
  if (!res.ok) {
    throw new Error(`GET ${redirectUri} failed: ${res.status} ${await res.text()}`);
  }

  const data = await res.json();
  console.log('Redirect URI Response:');
  console.log(JSON.stringify(data, null, 2));
}
