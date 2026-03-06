import bs58 from 'bs58';

const X_BASE64URL = '...';
const Y_BASE64URL = '...';

function createDidKey(xBase64url: string, yBase64url: string) {
  // 轉回 Buffer
  const x = Buffer.from(xBase64url, 'base64url');
  const y = Buffer.from(yBase64url, 'base64url');

  // 根據 Y 的最後一個 byte 判斷是奇數還是偶數來決定 prefix (0x02 偶數, 0x03 奇數)
  const prefix = y[y.length - 1] % 2 === 0 ? 0x02 : 0x03;

  // 組合出 33 bytes 的 Compressed Public Key
  const pubKey = Buffer.concat([Buffer.from([prefix]), x]);

  // 加上 P-256 的 multicodec (0x1200)
  const multicodec = Buffer.from([0x80, 0x24]);
  const bytes = Buffer.concat([multicodec, pubKey]);

  // Base58 編碼並加上 did:key:z 開頭
  const correctDidKey = 'did:key:z' + bs58.encode(bytes);
  console.log(correctDidKey);
}

createDidKey(X_BASE64URL, Y_BASE64URL);
