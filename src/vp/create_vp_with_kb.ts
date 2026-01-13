import { getIdentity } from '../util';
import {
  Duration,
  JwsSignatureOptions,
  KeyBindingJwtClaims,
  SdJwt,
  Timestamp,
} from '@iota/identity-wasm/node';

const HOLDER_SECRET_KEY = '...';
const HOLDER_DID = '...';

const PRESENTATION_NONCE = '...';
const VERIFIER_DID = '...';
const SD_JWT = '...';

async function createVpWithKeyBinding() {
  console.log('===========================================================================');
  console.log('\tStep 1: Get holder identity.');
  console.log('===========================================================================');

  // Holder
  const [holderClient, holderStorage, holderDocument, holderMethodFragment] = await getIdentity(
    HOLDER_SECRET_KEY,
    HOLDER_DID,
  );
  console.log(`Holder Document:\n${JSON.stringify(holderDocument, null, 2)}`);

  // ===========================================================================
  // Step 2: Holder creates a verifiable presentation from the issued credential for the verifier to validate.
  // ===========================================================================

  const expires = Timestamp.nowUTC().checkedAdd(Duration.minutes(10));

  const sdJwtReceived = SdJwt.parse(SD_JWT);
  const receivedDisclosures = sdJwtReceived.disclosures();
  const bindingClaims = new KeyBindingJwtClaims(
    sdJwtReceived.jwt(),
    receivedDisclosures,
    PRESENTATION_NONCE,
    VERIFIER_DID,
    Timestamp.nowUTC(),
  );
  const kbJwt = await holderDocument.createJws(
    holderStorage,
    holderMethodFragment,
    bindingClaims.toString(),
    new JwsSignatureOptions({
      typ: KeyBindingJwtClaims.keyBindingJwtHeaderTyp(),
    }),
  );
  const kbJwtString = kbJwt.toString();
  const sdJwtWithKb = new SdJwt(sdJwtReceived.jwt().toString(), receivedDisclosures, kbJwtString);
  const presentation = sdJwtWithKb.presentation();

  console.log('Presentation: ', presentation);
}

createVpWithKeyBinding().catch((error) => {
  console.error('Example error:', error);
});
