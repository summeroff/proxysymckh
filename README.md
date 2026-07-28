# Node.js proxy server for symchk

Local HTTP proxy in front of a private symbol store (often S3) so **symchk** and **Visual Studio** can fetch PDBs reliably.

## Problems this solves

1. **403 on missing keys** — S3 with `ListBucket` disabled returns `403` for objects that do not exist. `symchk` / VS treat `403` as “stop” and never try the compressed `.pd_` twin. A `404` makes them continue.
2. **Chunked responses** — `symchk` does not handle `Transfer-Encoding: chunked`. This proxy always answers successful downloads with a real **`Content-Length`** (stream when upstream provides length; otherwise buffer then send).
3. **Noisy system PDB traffic** — optional local skip list returns `404` for known Windows/NVIDIA PDB basenames without hitting upstream (paths like `/ntdll.pdb/<GUID>/ntdll.pdb` match by basename).

No npm dependencies — Node.js standard library only.

## Requirements

- [Node.js](https://nodejs.org/) 18+ (20/22 fine)

## Install

```bash
git clone https://github.com/summeroff/proxysymckh.git
cd proxysymckh
# nothing to install
```

## Usage

```bash
node index.js <remote-server-url> [port]
```

| Argument | Required | Default | Example |
|----------|----------|---------|---------|
| remote-server-url | yes | — | `https://yoursymbolsserver.com` or `https://bucket.s3.amazonaws.com/symbols` |
| port | no | `3000` | `4000` |

Examples:

```bash
node index.js https://yoursymbolsserver.com
node index.js https://yoursymbolsserver.com 4000
npm start -- https://yoursymbolsserver.com 3000
```

Point clients at `http://localhost:3000` (or your port). Inbound paths are appended to the remote base URL.

## Visual Studio

1. **Tools** → **Options** → **Debugging** → **Symbols**
2. Add symbol file location: `http://localhost:3000`  
   (or `http://localhost:3000/symbols` if that matches how your upstream is laid out)
3. **OK**

## Testing with symchk

1. Pick a binary whose PDB lives on your symbol server.
2. Open a prompt where `symchk` is available (often  
   `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64`).
3. Run (adjust paths):

```bat
symchk /vvvv "<path to binary>" /s srv*c:\some_temp*http://localhost:3000
```

If the layout on the server includes a `/symbols` prefix, use that in the URL:

```bat
symchk /vvvv "<path to binary>" /s srv*c:\some_temp*http://localhost:3000/symbols
```

Successful-ish summary lines look like:

```text
SYMCHK: FAILED files = 0
SYMCHK: PASSED + IGNORED files = 1
```

## Behavior notes

| Upstream | Proxy responds |
|----------|----------------|
| `200` + `Content-Length` | `200`, same length, streamed |
| `200` without length | `200`, body buffered, `Content-Length` set |
| `403` | `404` (empty) |
| other 4xx/5xx | same status (empty body) |
| skip-list basename | `404` without upstream call |
| redirect (3xx) | followed (max 5) |
| client disconnect | upstream request aborted |

Skip list is the hardcoded basename set in `index.js` (ntdll, kernelbase, common NVIDIA CUDA PDBs, etc.). Edit the array if you need different names.

## License

MIT
