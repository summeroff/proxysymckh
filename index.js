'use strict';

const http = require('http');
const https = require('https');
const { URL } = require('url');
const net = require('net');

const DEFAULT_PORT = 3000;
const UPSTREAM_TIMEOUT_MS = 60_000;
const MAX_REDIRECTS = 5;
/** Cap when buffering a body that has no Content-Length (avoids OOM). */
const MAX_BUFFER_BYTES = 512 * 1024 * 1024; // 512 MiB

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

/**
 * Symbol stems (name.pdb) that will never live on a private product symbol store.
 * Matched against the SymSrv folder segment, so .pdb / .pd_ / file.ptr all short-circuit.
 * Local response is 403 so clients stop probing deeper (unlike 404, which triggers .pd_).
 *
 * Do NOT put first-party stems here (obs*, libobs*, win-capture, mediasoup-*, …).
 */
const DENY_STEMS = new Set(
  [
    // Original fast-skip list
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

    // Core Windows / Win32 (from real slobs-symbol traffic)
    'kernel32.pdb',
    'user32.pdb',
    'win32u.pdb',
    'gdi32.pdb',
    'ucrtbase.pdb',
    'rpcrt4.pdb',
    'combase.pdb',
    'msvcp_win.pdb',
    'ole32.pdb',
    'oleaut32.pdb',
    'advapi32.pdb',
    'msvcrt.pdb',
    'sechost.pdb',
    'ws2_32.pdb',
    'avrt.pdb',
    'winmm.pdb',
    'powrprof.pdb',
    'pdh.pdb',
    'version.pdb',
    'secur32.pdb',
    'bcrypt.pdb',
    'bcryptprimitives.pdb',
    'sspicli.pdb',
    'wldap32.pdb',
    'crypt32.pdb',
    'cryptbase.pdb',
    'cryptsp.pdb',
    'cryptnet.pdb',
    'imm32.pdb',
    'UMPDC.pdb',
    'umppc.pdb',
    'shcore.pdb',
    'shlwapi.pdb',
    'Kernel.Appcore.pdb',
    'ntmarta.pdb',
    'perfos.pdb',
    'PfClient.pdb',
    'rtworkq.pdb',
    'uxtheme.pdb',
    'WscApi.pdb',
    'CLBCatQ.pdb',
    'cfgmgr32.pdb',
    'profapi.pdb',
    'msasn1.pdb',
    'wldp.pdb',
    'drvstore.pdb',
    'devobj.pdb',
    'imagehlp.pdb',
    'rsaenh.pdb',
    'WinTypes.pdb',
    'msdmo.pdb',
    'setupapi.pdb',
    'dbghelp.pdb',
    'userenv.pdb',
    'winhttp.pdb',
    'DWrite.pdb',
    'winspool.pdb',
    'dhcpcsvc.pdb',
    'dhcpcsvc6.pdb',
    'dpapi.pdb',
    'avicap32.pdb',
    'msvfw32.pdb',
    'comctl32v582.pdb',
    'gdiplus.pdb',
    'msctf.pdb',
    'mswsock.pdb',
    'dnsapi.pdb',
    'dsparse.pdb',
    'nsi.pdb',
    'rasadhlp.pdb',
    'fwpuclnt.pdb',
    'hid.pdb',
    'devenum.pdb',
    'opengl32.pdb',
    'glu32.pdb',
    'schannel.pdb',
    'MMDevAPI.pdb',
    'audioses.pdb',
    'Windows.UI.pdb',
    'ncrypt.pdb',
    'ntasn1.pdb',
    'ncryptsslp.pdb',
    'ResourcePolicyClient.pdb',
    'WindowsCodecs.pdb',
    'nlansp_c.pdb',
    'wtsapi32.pdb',
    'winsta.pdb',
    'mscms.pdb',
    'icm32.pdb',
    'quartz.pdb',
    'wkscli.pdb',
    'netutils.pdb',
    'qcap.pdb',
    'MFKsProxy.pdb',
    'atl.pdb',
    'mfsensorgroup.pdb',
    'MFPLAT.pdb',
    'FrameServerMonitorClient.pdb',
    'policymanager.pdb',
    'mfcore.pdb',
    'FrameServerClient.pdb',
    'gpapi.pdb',
    'Windows.Media.MediaControl.pdb',
    'MFReadWrite.pdb',
    'kswdmcap.pdb',
    'vidcap.pdb',
    'msimg32.pdb',
    'msxml3.pdb',
    'coml2.pdb',
    'WINMMBASE.pdb',
    'wdmaud.pdb',
    'wdmaud2.pdb',
    'msacm32.pdb',
    'midimap.pdb',
    'dcomp.pdb',
    'Microsoft.Internal.WarpPal.pdb',
    'dwmapi.pdb',
    'dxgi.pdb',
    'd3d9.pdb',
    'd3d11.pdb',
    'DXCore.pdb',
    'directxdatabasehelper.pdb',

    // MSVC redistributable
    'vcruntime140.amd64.pdb',
    'vcruntime140_1.amd64.pdb',
    'msvcp140.amd64.pdb',

    // NVIDIA driver / toolkit (not product store)
    'nvldumdx.pdb',
    'nvgpucomp64.pdb',
    'NvMemMapStoragex.pdb',
    'nvwgf2umx.pdb',
    'NVAudioEffects.pdb',
    'NVTRTLogger.pdb',
    'nvapi64_impl.pdb',
    'nvdxgdmal.pdb',
    'nvobjectloader.pdb',
    'nvEncodeAPI64.pdb',
    'NvVirtualCameraFilter_x64.pdb',

    // NOTE: libcef.dll.pdb / chrome_elf.dll.pdb are NOT denied — Streamlabs ships
    // a private CEF build and uploads those PDBs to the product symbol store.

    // Other third-party never on store (from real traffic)
    'libcrypto-1_1-x64.pdb',
    'LogiCam.pdb',
  ].map((s) => s.toLowerCase())
);

// After upstream proves a SymSrv folder is empty (.pd_ miss), remember it for this process.
// Key: "name.pdb/<guid>" (lowercased). Value: timestamp ms.
const deadFolders = new Map();
const DEAD_FOLDER_TTL_MS = 60 * 60 * 1000; // 1h; process restart clears too
const DEAD_FOLDER_MAX = 5000;

function requestPathname(urlPath) {
  const noQuery = (urlPath || '/').split('?')[0];
  try {
    return decodeURIComponent(noQuery);
  } catch {
    return noQuery;
  }
}

/**
 * Parse SymSrv-style path:
 *   /symbols/foo.pdb/<GUID>/foo.pdb
 *   /symbols/foo.pdb/<GUID>/foo.pd_
 *   /symbols/foo.pdb/<GUID>/file.ptr
 *   /symbols/index2.txt
 */
function parseSymbolPath(urlPath) {
  const pathname = requestPathname(urlPath);
  const parts = pathname.split('/').filter(Boolean);
  const leaf = (parts[parts.length - 1] || '').toLowerCase();

  // Prefer the folder segment that ends with .pdb (SymSrv layout).
  let stem = null;
  let stemIdx = -1;
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    if (/\.pdb$/i.test(p)) {
      stem = p.toLowerCase();
      stemIdx = i;
      break;
    }
  }

  // Fallback: leaf foo.pd_ → foo.pdb
  if (!stem && /\.pd_$/i.test(leaf)) {
    stem = `${leaf.slice(0, -4)}.pdb`;
  } else if (!stem && /\.pdb$/i.test(leaf)) {
    stem = leaf;
  }

  let guid = null;
  if (stemIdx >= 0 && parts[stemIdx + 1]) {
    guid = parts[stemIdx + 1].toLowerCase();
  }

  const folderKey = stem && guid ? `${stem}/${guid}` : null;

  let kind = 'other';
  if (leaf === 'index2.txt' || leaf === 'index.txt' || leaf === 'pingme.txt') {
    kind = 'index';
  } else if (leaf === 'file.ptr') {
    kind = 'ptr';
  } else if (/\.pd_$/i.test(leaf)) {
    kind = 'pd_';
  } else if (/\.pdb$/i.test(leaf)) {
    kind = 'pdb';
  }

  return { pathname, leaf, stem, guid, folderKey, kind };
}

function pruneDeadFolders(now) {
  if (deadFolders.size <= DEAD_FOLDER_MAX) {
    for (const [k, t] of deadFolders) {
      if (now - t > DEAD_FOLDER_TTL_MS) deadFolders.delete(k);
    }
    return;
  }
  // Hard cap: drop oldest half
  const entries = [...deadFolders.entries()].sort((a, b) => a[1] - b[1]);
  const drop = Math.ceil(entries.length / 2);
  for (let i = 0; i < drop; i++) deadFolders.delete(entries[i][0]);
}

function markFolderDead(folderKey) {
  if (!folderKey) return;
  const now = Date.now();
  deadFolders.set(folderKey, now);
  if (deadFolders.size > DEAD_FOLDER_MAX) pruneDeadFolders(now);
}

function isFolderDead(folderKey) {
  if (!folderKey) return false;
  const t = deadFolders.get(folderKey);
  if (t == null) return false;
  if (Date.now() - t > DEAD_FOLDER_TTL_MS) {
    deadFolders.delete(folderKey);
    return false;
  }
  return true;
}

function joinRemoteUrl(reqUrl) {
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
 * Block open redirects into unexpected private targets (SSRF).
 * Always allow hops that stay on the configured upstream host or the current
 * response host (so local dev + same-host S3 redirects work). Cross-host hops
 * must be public http(s) only.
 */
function isForbiddenRedirectTarget(nextUrl, fromUrl) {
  if (nextUrl.protocol !== 'http:' && nextUrl.protocol !== 'https:') {
    return `unsupported protocol ${nextUrl.protocol}`;
  }
  if (nextUrl.username || nextUrl.password) {
    return 'URL userinfo not allowed';
  }
  const host = (nextUrl.hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!host) return 'empty host';

  const configured = (remoteBase.hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  const previous = (fromUrl.hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (host === configured || host === previous) {
    return null;
  }

  if (host === 'localhost' || host.endsWith('.localhost') || host === 'metadata.google.internal') {
    return `blocked host ${host}`;
  }

  if (net.isIP(host) === 4) {
    const [a, b] = host.split('.').map((x) => parseInt(x, 10));
    if (a === 0 || a === 10 || a === 127) return `blocked IPv4 ${host}`;
    if (a === 169 && b === 254) return `blocked IPv4 ${host}`;
    if (a === 192 && b === 168) return `blocked IPv4 ${host}`;
    if (a === 172 && b >= 16 && b <= 31) return `blocked IPv4 ${host}`;
  } else if (net.isIP(host) === 6) {
    const h = host.toLowerCase();
    if (h === '::1' || h.startsWith('fe80:') || h.startsWith('fc') || h.startsWith('fd')) {
      return `blocked IPv6 ${host}`;
    }
    if (h.includes('.')) {
      const m = h.match(/(\d+\.\d+\.\d+\.\d+)$/);
      if (m) {
        const fake = new URL(`http://${m[1]}/`);
        const why = isForbiddenRedirectTarget(fake, fromUrl);
        if (why) return why;
      }
    }
  }
  return null;
}

/**
 * GET upstream. Follows redirects (public hosts only). Invokes onResponse(err, incomingMessage).
 * Returns the active ClientRequest so the caller can abort on client disconnect.
 */
function upstreamGet(url, redirectsLeft, onResponse) {
  const lib = url.protocol === 'http:' ? http : https;
  const req = lib.get(
    url,
    {
      timeout: UPSTREAM_TIMEOUT_MS,
      headers: {
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
        const blocked = isForbiddenRedirectTarget(next, url);
        if (blocked) {
          onResponse(new Error(`Refusing redirect to ${next.href}: ${blocked}`));
          return;
        }
        console.log(`Redirect ${code} → ${next.href}`);
        const child = upstreamGet(next, redirectsLeft - 1, onResponse);
        req._proxysymChild = child;
        return;
      }
      onResponse(null, upRes);
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

  const chunks = [];
  let total = 0;
  let aborted = false;
  upRes.on('data', (chunk) => {
    if (aborted) return;
    total += chunk.length;
    if (total > MAX_BUFFER_BYTES) {
      aborted = true;
      console.error(
        `Upstream body exceeded buffer cap ${MAX_BUFFER_BYTES} bytes (no Content-Length); aborting`
      );
      upRes.destroy();
      sendEmpty(res, 502);
      return;
    }
    chunks.push(chunk);
  });
  upRes.on('end', () => {
    if (aborted || res.headersSent || res.writableEnded) return;
    const buf = Buffer.concat(chunks, total);
    console.log(`Buffered ${buf.length} bytes (no upstream Content-Length)`);
    sendBodyWithLength(res, 200, contentType, buf);
  });
  upRes.on('error', (err) => {
    if (aborted) return;
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
  const parsed = parseSymbolPath(urlPath);

  // Useless listing / ping files on private stores.
  if (parsed.kind === 'index') {
    console.log(`Deny (index): ${urlPath} → 403`);
    sendEmpty(res, 403);
    return;
  }

  // Static deny: whole symbol family (.pdb / .pd_ / file.ptr) → 403 so client stops.
  if (parsed.stem && DENY_STEMS.has(parsed.stem)) {
    console.log(`Deny (stem ${parsed.stem}): ${urlPath} → 403`);
    sendEmpty(res, 403);
    return;
  }

  // Learned empty folder (after upstream .pd_ miss, etc.).
  if (parsed.folderKey && isFolderDead(parsed.folderKey)) {
    console.log(`Deny (cached miss ${parsed.folderKey}): ${urlPath} → 403`);
    sendEmpty(res, 403);
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

    // S3 "no such key" → 403. Map to 404 so symchk/VS still try .pd_ (core purpose).
    // After a compressed twin also misses, mark the GUID folder dead → later probes get 403.
    if (code === 403 || code === 404) {
      settled = true;
      discardBody(upRes);

      if (parsed.kind === 'pd_' || parsed.kind === 'ptr') {
        // .pd_ gone (or ptr) ⇒ nothing left in this folder worth fetching.
        markFolderDead(parsed.folderKey);
        console.log(
          `Mapped upstream ${code} → 404 for ${urlPath}` +
            (parsed.folderKey ? ` (folder cached dead: ${parsed.folderKey})` : '')
        );
      } else if (code === 403) {
        console.log(`Mapped upstream 403 → 404 for ${urlPath}`);
      } else {
        console.log(`Upstream 404 for ${urlPath}`);
      }

      // Always 404 to the client for upstream miss on first-party-unknown paths so
      // a .pdb miss still allows the .pd_ attempt. Folder cache handles the rest with 403.
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
      const contentType = upRes.headers['content-type'] || 'application/octet-stream';
      const lenHeader = upRes.headers['content-length'];
      if (lenHeader && /^\d+$/.test(String(lenHeader))) {
        discardBody(upRes);
        res.statusCode = 200;
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Length', String(lenHeader));
        res.end();
        return;
      }
      // No Content-Length: count bytes while discarding so HEAD does not lie with 0.
      let total = 0;
      let aborted = false;
      upRes.on('data', (chunk) => {
        if (aborted) return;
        total += chunk.length;
        if (total > MAX_BUFFER_BYTES) {
          aborted = true;
          upRes.destroy();
          console.error(`HEAD count exceeded buffer cap ${MAX_BUFFER_BYTES}; aborting`);
          sendEmpty(res, 502);
        }
      });
      upRes.on('end', () => {
        if (aborted || res.headersSent || res.writableEnded) return;
        res.statusCode = 200;
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Length', String(total));
        res.end();
      });
      upRes.on('error', (err) => {
        if (aborted) return;
        console.error(`HEAD upstream error: ${err.message}`);
        sendEmpty(res, 502);
      });
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
  console.log(`Deny stems: ${DENY_STEMS.size}; negative-cache TTL ${DEAD_FOLDER_TTL_MS / 1000}s`);
});

server.on('error', (err) => {
  console.error(`Server error: ${err.message}`);
  process.exit(1);
});
