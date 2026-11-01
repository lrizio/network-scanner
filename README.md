# Network Scanner

Web dashboard that finds devices with a scapy ARP sweep, then runs nmap service/version
detection and OS fingerprinting on each one.

> Only scan networks you own or have written permission to test.

## Standalone app (Windows) - no Python needed

The ready-to-use package is in [`build/`](build):

| File | Purpose |
|------|---------|
| `NetworkScanner.exe` | The app (Python, Flask, scapy and python-nmap embedded; prompts for Administrator) |
| `nmap/` | Portable Nmap used by the app - keep it next to the exe |
| `USER_GUIDE.html` | Offline user guide (also at `/guide` inside the app) |

Copy the whole `build` folder anywhere, install [Npcap](https://npcap.com) once, double-click
`NetworkScanner.exe` and accept the UAC prompt. The console prints a clickable link and the
dashboard opens in your browser.

### Rebuilding the exe

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
# optional: -NmapDir "D:\Tools\Nmap"   (source of the bundled nmap folder)
```

`build.ps1` creates a private `.buildenv` virtualenv, installs the requirements plus PyInstaller,
builds a one-file exe with an Administrator manifest, copies the runtime files of your Nmap install
into `build\nmap`, and copies the guide. `.buildenv` can be deleted afterwards.

Licensing note: Nmap is released under the [Nmap Public Source License](https://nmap.org/npsl/);
bundling it is fine for personal/internal use, but redistributing this package to others needs an
Nmap OEM licence. Npcap is not bundled (its free licence forbids redistribution) - users install it themselves.

## Running from source

Prerequisites: Python 3.9+, [Nmap](https://nmap.org/download.html) (Windows: also installs Npcap), or
`sudo apt install python3-venv nmap` / `brew install nmap`.

```bash
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

Run from an elevated shell (raw ARP packets and nmap OS detection need it):

```powershell
.\.venv\Scripts\python.exe app.py          # Windows: PowerShell as Administrator
```
```bash
sudo .venv/bin/python app.py               # Linux/macOS
```

Options: `--port 8080`, `--no-browser`, `--host` (default `127.0.0.1`; the API has no
authentication - don't expose it on an untrusted network).

## Behaviour notes

- **Phases:** Discovery (ARP, `/24` chunks) -> Deep Inspection (up to 4 parallel nmap jobs).
- **ARP only reaches your local subnet.** Otherwise it falls back to an nmap ping sweep (MAC may be blank).
  Your own machine does not answer its own ARP request, so it isn't listed.
- **Not elevated?** OS fingerprinting is skipped; "Likely OS" is inferred from service banners.
- **Manufacturer** comes from nmap's `nmap-mac-prefixes`; randomised MACs show as "Private".
- **Safety limits:** private (RFC1918) ranges only, nothing larger than a `/16`
  (`SCANNER_ALLOW_PUBLIC=1` lifts the private-only rule).
- The dashboard page loads Bootstrap from a CDN, so the browser needs internet access.
