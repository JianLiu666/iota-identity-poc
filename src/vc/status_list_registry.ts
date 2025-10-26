import { createServer, IncomingMessage, ServerResponse } from 'http';
import { readFile, writeFile, mkdir, access } from 'fs/promises';
import { constants as fsConstants } from 'fs';
import path from 'path';

const DEFAULT_PORT = Number(process.env.STATUS_LIST_PORT ?? 8787);
const DEFAULT_HOST = process.env.STATUS_LIST_HOST ?? '0.0.0.0';
const DEFAULT_DIR =
  process.env.STATUS_LIST_DIR ?? path.resolve(process.cwd(), 'public', 'vc', 'status');
const DEFAULT_FILE = process.env.STATUS_LIST_FILE ?? path.join(DEFAULT_DIR, 'revocation.json');

type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

async function ensureDirectoryExists(targetDir: string): Promise<void> {
  try {
    await access(targetDir, fsConstants.F_OK);
  } catch {
    await mkdir(targetDir, { recursive: true });
  }
}

async function readRequestBody(req: IncomingMessage): Promise<string> {
  return await new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
    });
    req.on('end', () => resolve(data));
    req.on('error', (err) => reject(err));
  });
}

function setCors(res: ServerResponse): void {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

function sendJson(
  res: ServerResponse,
  statusCode: number,
  body: JsonValue,
  contentType: string = 'application/ld+json; charset=utf-8',
): void {
  const payload = typeof body === 'string' ? body : JSON.stringify(body);
  res.statusCode = statusCode;
  res.setHeader('Content-Type', contentType);
  res.setHeader('Cache-Control', 'no-store');
  res.end(payload);
}

function sendText(res: ServerResponse, statusCode: number, text: string): void {
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(text);
}

async function getStatusListJson(): Promise<string> {
  return await readFile(DEFAULT_FILE, 'utf8');
}

async function saveStatusListJson(jsonString: string): Promise<void> {
  await ensureDirectoryExists(path.dirname(DEFAULT_FILE));
  await writeFile(DEFAULT_FILE, jsonString, 'utf8');
}

function isLikelyStatusList2021Credential(obj: any): boolean {
  if (obj == null || typeof obj !== 'object') return false;
  if (!('credentialSubject' in obj)) return false;
  const subject: any = (obj as any).credentialSubject;
  if (subject == null || typeof subject !== 'object') return false;
  // Check for encodedList presence; minimal heuristic
  return 'encodedList' in subject && typeof subject.encodedList === 'string';
}

const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  setCors(res);

  // Basic request logging
  const startedAt = Date.now();
  const method = req.method ?? 'UNKNOWN';
  const originalUrl = req.url ?? '/';
  const remoteAddr = (req.headers['x-forwarded-for'] as string) ?? req.socket.remoteAddress ?? '';
  const contentLength = req.headers['content-length'] ?? 'unknown';
  // eslint-disable-next-line no-console
  console.log(
    `[${new Date().toISOString()}] ${method} ${originalUrl} from ${remoteAddr} len=${contentLength}`,
  );
  res.on('finish', () => {
    const durationMs = Date.now() - startedAt;
    // eslint-disable-next-line no-console
    console.log(
      `[${new Date().toISOString()}] Completed ${method} ${originalUrl} -> ${res.statusCode} in ${durationMs}ms`,
    );
  });

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    res.end();
    return;
  }

  const url = (req.url ?? '/').split('?')[0];

  try {
    if (req.method === 'GET' && url === '/health') {
      sendText(res, 200, 'ok');
      return;
    }

    if (req.method === 'GET' && (url === '/status' || url === '/credential/status')) {
      try {
        const json = await getStatusListJson();
        sendJson(res, 200, json);
      } catch (e: any) {
        sendText(res, 404, 'status list not found');
      }
      return;
    }

    if (req.method === 'POST' && (url === '/status' || url === '/credential/status')) {
      const raw = await readRequestBody(req);
      const sizeBytes = Buffer.byteLength(raw, 'utf8');
      const preview = raw.length > 512 ? `${raw.slice(0, 512)}…` : raw;
      // eslint-disable-next-line no-console
      console.log(
        `[${new Date().toISOString()}] POST body size=${sizeBytes}B preview=${JSON.stringify(preview)}`,
      );
      if (!raw || raw.trim().length === 0) {
        sendText(res, 400, 'empty body');
        return;
      }
      try {
        const parsed = JSON.parse(raw);
        if (!isLikelyStatusList2021Credential(parsed)) {
          sendText(res, 400, 'invalid StatusList2021Credential payload');
          return;
        }
        const pretty = JSON.stringify(parsed, null, 2);
        await saveStatusListJson(pretty);
        sendJson(res, 200, pretty);
      } catch (err: any) {
        sendText(res, 400, 'invalid JSON');
      }
      return;
    }

    // Fallback
    sendText(res, 404, 'not found');
  } catch (err: any) {
    sendText(res, 500, 'internal error');
  }
});

server.listen(DEFAULT_PORT, DEFAULT_HOST, () => {
  const addr = `${DEFAULT_HOST}:${DEFAULT_PORT}`;
  // eslint-disable-next-line no-console
  console.log(`StatusList server listening at http://${addr}`);
  // eslint-disable-next-line no-console
  console.log(`GET  /health`);
  // eslint-disable-next-line no-console
  console.log(`GET  /status`);
  // eslint-disable-next-line no-console
  console.log(`POST /status`);
  // eslint-disable-next-line no-console
  console.log(`File: ${DEFAULT_FILE}`);
});
