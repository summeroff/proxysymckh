'use strict';

const http = require('http');
const https = require('https');
const { URL } = require('url');
const path = require('path');

const DEFAULT_PORT = 3000;
const UPSTREAM_TIMEOUT_MS = 60_000;
const MAX_REDIRECTS = 5;

const args = process.argv.slice(2);
if (args.length < 1 || args[0] === '-h' || args[0] === '--help') {
  console.log('Usage: node index.js <remote-server-url> [port=3000]');
  console.log('Example: node index.js https://yoursymbolsserver.com 3000');
  process.exit(args.length < 1 ? 1 : 0);
}

const remoteServerUrl = args[0].replace(/\/+$/, '');
const serverPort = parseInt(args[1] || String(DEFAULT_PORT), 10);
if (!Number.isFinite(serverPort) || serverPort < 1 || serverPort > 65535) {
  console.error(`Invalid port: ${args[1]}`);
  process.exit(1);
}

let remoteBase;
try {
  remoteBase = new URL(remoteServerUrl.includes('://') ? remoteServerUrl : `https://${remoteServerUrl}`);
} catch (err) {
  console.error(`Invalid remote-server-url: ${remoteServerUrl}`);
  process.exit(1);
}

// Basenames to skip without hitting upstream (system / vendor PDBs you do not host).
// Matched case-insensitively against the last path segment (works with /name.pdb/GUID/name.pdb).
const skipBasenames = new Set(
  [
    'ntdll.pdb',
    'kernelbase.pdb',
    'gdi32full.pdb',
    'shell32.pdb',
    'Windows.Storage.pdb',
    'urlmon.pdb',
    'iertutil.pdb',
    'iphlpapi.pdb',
    'wintrust.pdb',
    'UIAutomationCore.pdb',
    'wevtapi.pdb',
    'TextInputFramework.pdb',
    'CoreMessaging.pdb',
    'D3DCompiler_47.pdb',
    'nvcuvid64.pdb',
    'nvcuda_loader.pdb',
    'nvcuda.pdb',
    'nvapi64.pdb',
    'TextShaping.pdb',
  ].map((name) => name.toLowerCase())
);

function requestPathname(urlPath) {
  const noQuery = (urlPath || '/').split('?')[0];
  try {
    return decodeURIComponent(noQuery);
  } catch {
    return noQuery;
  }
}

function basenameOfUrlPath(urlPath) {
  const pathname = requestPathname(urlPath);
  const base = path.posix.basename(pathname);
  return base.toLowerCase();
}

function joinRemoteUrl(reqUrl) {
  // Preserve path + query from the inbound request on top of the remote origin/base path.
  const inbound = new URL(reqUrl || '/', 'http://localhost');
  const target = new URL(remoteBase.href);
  const basePath = remoteBase.pathname.replace(/\/+$/, '');
  const reqPath = inbound.pathname.startsWith('/') ? inbound.pathname : `/${inbound.pathname}`;
  target.pathname = `${basePath}${reqPath}`.replace(/\/{2,}/g, '/');
    target.search = inbound.search;
    return target;
  }

function discardBody(stream) {
  stream.resume();
}

function sendEmpty(res, statusCode) {
  if (res.headersSent || res.writableEnded) return;
  res.statusCode = statusCode;
  res.setHeader('Content-Length', '0');
  res.end();
}

/**
 * GET upstream. Follows redirects. Invokes onResponse(err, incomingMessage, request).
 * Returns the active ClientRequest so the caller can abort on client disconnect.
 */
function upstreamGet(url, redirectsLeft, onResponse) {
  const lib = url.protocol === 'http:' ? http : https;
  const req = lib.get(
    url,
    {
      timeout: UPSTREAM_TIMEOUT_MS,
      headers: {
        // Prefer identity so we can forward Content-Length when present.
        'Accept-Encoding': 'identity',
      },
    },
    (upRes) => {
      const code = upRes.statusCode || 0;
      if ([301, 302, 303, 307, 308].includes(code) && upRes.headers.location && redirectsLeft > 0) {
        discardBody(upRes);
        let next;
        try {
          next = new URL(upRes.headers.location, url);
        } catch (err) {
          onResponse(new Error(`Bad redirect Location: ${upRes.headers.location}`));
          return;
        }
        console.log(`Redirect ${code} → ${next.href}`);
        const child = upstreamGet(next, redirectsLeft - 1, onResponse);
        // Re-bind destroy so client abort cancels the latest hop.
        req._proxysymChild = child;
        return;
      }
      onResponse(null, upRes, req);
    }
  );

  req.on('timeout', () => {
    req.destroy(new Error(`Upstream timeout after ${UPSTREAM_TIMEOUT_MS}ms`));
  });
  req.on('error', (err) => {
    onResponse(err);
  });

  const origDestroy = req.destroy.bind(req);
  req.destroy = (err) => {
    if (req._proxysymChild) {
      try {
        req._proxysymChild.destroy(err);
      } catch {
        /* ignore */
      }
    }
    return origDestroy(err);
  };

  return req;
}

/**
 * Respond with a full body that always has Content-Length (never chunked).
 * symchk does not handle Transfer-Encoding: chunked.
 */
function sendBodyWithLength(res, statusCode, contentType, bodyBuf) {
  if (res.headersSent || res.writableEnded) return;
  res.statusCode = statusCode;
  res.setHeader('Content-Type', contentType || 'application/octet-stream');
  res.setHeader('Content-Length', String(bodyBuf.length));
  res.end(bodyBuf);
}

function pipeOrBufferOk(upRes, res) {
  const contentType = upRes.headers['content-type'] || 'application/octet-stream';
  const lenHeader = upRes.headers['content-length'];

  if (lenHeader && /^\d+$/.test(String(lenHeader))) {
    // Fast path: upstream length known → stream and keep Content-Length (no chunked).
    res.statusCode = 200;
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Length', String(lenHeader));
    if (upRes.headers['last-modified']) {
      res.setHeader('Last-Modified', upRes.headers['last-modified']);
    }
    if (upRes.headers.etag) {
      res.setHeader('ETag', upRes.headers.etag);
    }
    upRes.pipe(res);
    upRes.on('error', (err) => {
      console.error(`Upstream stream error: ${err.message}`);
      res.destroy(err);
    });
    return;
  }

  // No Content-Length (or non-numeric): buffer entire body, then send with length.
  const chunks = [];
  let total = 0;
  upRes.on('data', (chunk) => {
    chunks.push(chunk);
    total += chunk.length;
  });
  upRes.on('end', () => {
    const buf = Buffer.concat(chunks, total);
    console.log(`Buffered ${buf.length} bytes (no upstream Content-Length)`);
    sendBodyWithLength(res, 200, contentType, buf);
  });
  upRes.on('error', (err) => {
    console.error(`Upstream buffer error: ${err.message}`);
    sendEmpty(res, 502);
  });
}

const server = http.createServer((req, res) => {
  const method = req.method || 'GET';
  if (method !== 'GET' && method !== 'HEAD') {
    res.setHeader('Allow', 'GET, HEAD');
    sendEmpty(res, 405);
    return;
  }

  const urlPath = req.url || '/';
  const base = basenameOfUrlPath(urlPath);

  if (base && skipBasenames.has(base)) {
    console.log(`Skip (local): ${urlPath} → 404`);
    sendEmpty(res, 404);
    return;
  }

  let target;
  try {
    target = joinRemoteUrl(urlPath);
  } catch (err) {
    console.error(`Bad request URL: ${urlPath}`);
    sendEmpty(res, 400);
    return;
  }

  console.log(`${method} ${urlPath} → ${target.href}`);

  let settled = false;
  const finishErr = (status, msg) => {
    if (settled) return;
    settled = true;
    if (msg) console.error(msg);
    sendEmpty(res, status);
  };

  const upReq = upstreamGet(target, MAX_REDIRECTS, (err, upRes) => {
    if (err) {
      finishErr(502, `Upstream error: ${err.message}`);
      return;
    }
    if (settled || res.writableEnded) {
      discardBody(upRes);
      return;
    }

    const code = upRes.statusCode || 0;

    // Core purpose of this proxy: S3 "no such key" often arrives as 403; map to 404
    // so symchk / VS still try the compressed .pd_ twin.
    if (code === 403) {
      settled = true;
      discardBody(upRes);
      console.log(`Mapped upstream 403 → 404 for ${urlPath}`);
      sendEmpty(res, 404);
      return;
    }

    if (code !== 200) {
      settled = true;
      discardBody(upRes);
      console.log(`Upstream status ${code} for ${urlPath}`);
      sendEmpty(res, code >= 400 && code < 600 ? code : 502);
      return;
    }

    settled = true;
    if (method === 'HEAD') {
      discardBody(upRes);
      const contentType = upRes.headers['content-type'] || 'application/octet-stream';
      const lenHeader = upRes.headers['content-length'];
      res.statusCode = 200;
      res.setHeader('Content-Type', contentType);
      if (lenHeader && /^\d+$/.test(String(lenHeader))) {
        res.setHeader('Content-Length', String(lenHeader));
      } else {
        res.setHeader('Content-Length', '0');
      }
      res.end();
      return;
    }

    console.log(
      `Upstream 200 content-length=${upRes.headers['content-length'] || '(none)'} type=${upRes.headers['content-type'] || ''}`
    );
    pipeOrBufferOk(upRes, res);
  });

  const abortUpstream = () => {
    if (!upReq.destroyed) {
      upReq.destroy();
    }
  };

  req.on('aborted', abortUpstream);
  res.on('close', () => {
    if (!res.writableFinished) {
      abortUpstream();
    }
  });
});

server.listen(serverPort, () => {
  console.log(`proxysymckh listening on http://localhost:${serverPort}`);
  console.log(`Upstream: ${remoteBase.href}`);
});

server.on('error', (err) => {
  console.error(`Server error: ${err.message}`);
  process.exit(1);
});
