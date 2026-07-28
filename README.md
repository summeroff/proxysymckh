# Node.js proxy server for symchk

Local HTTP proxy in front of a private symbol store (often S3) so **symchk** and **Visual Studio** can fetch PDBs reliably.

## Problems this solves

1. **403 on missing keys** — S3 with `ListBucket` disabled returns `403` for objects that do not exist. `symchk` / VS treat `403` as “stop” and never try the compressed `.pd_` twin. A `404` makes them continue.
2. **Chunked responses** — `symchk` does not handle `Transfer-Encoding: chunked`. This proxy always answers successful downloads with a real **`Content-Length`** (stream when upstream provides length; otherwise buffer then send).
3. **Noisy system / third-party PDB traffic** — a deny list of Windows, MSVC, NVIDIA driver, … **symbol stems** (`name.pdb`) returns local **`403`** for the whole SymSrv family (`.pdb` / `.pd_` / `file.ptr`) so clients **stop probing**. That is different from upstream-miss **`404`**, which must stay so first-party `.pd_` twins are still tried. First-party / private CEF (`obs*`, `libobs*`, `libcef.dll`, …) are **not** denied.
4. **Negative cache** — after an upstream miss on `.pd_` (or `file.ptr`) for `name.pdb/<GUID>/…`, further probes under that folder get local **`403`** for the rest of the process (1h TTL).

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

| Case | Proxy responds | Why |
|------|----------------|-----|
| Upstream `200` + `Content-Length` | `200`, streamed | Normal download |
| Upstream `200` without length | `200`, buffered + `Content-Length` | Avoid chunked (symchk) |
| Upstream `403` / `404` on unknown stem | client **`404`** | Lets client try `.pd_` next (S3 miss) |
| After upstream miss on `.pd_` / `file.ptr` | folder cached; later probes **`403`** | Stop `file.ptr` / retries without S3 |
| Deny-list stem (`kernel32.pdb`, …) | **`403`** for `.pdb`/`.pd_`/`file.ptr` | Never on private store; stop family |
| `index2.txt` / `pingme.txt` | **`403`** | Useless on private S3 |
| redirect (3xx) | followed (max 5) | |
| client disconnect | upstream aborted | |

**Status split (important):**

- **`404` to client** = “not this file; try the compressed twin / next name” (needed for product PDBs on S3).
- **`403` to client** = “stop looking under this symbol” (deny list + negative cache).

Deny stems live in `DENY_STEMS` in `index.js`. Add names you know will never be uploaded; do **not** add first-party stems (`obs*`, `libobs*`, `libcef.dll`, `win-capture`, …).

## License

MIT
