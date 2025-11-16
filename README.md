# Chrome Remote Debugging Manager

`chrome-dev-tool-setup.ps1` is a PowerShell helper that launches Google Chrome with the DevTools protocol enabled and, when requested, exposes that debugger port over your WireGuard interface. It manages the entire lifecycle:

- Starts Chrome with an isolated user profile and the requested `--remote-debugging-port`.
- Optionally creates a `netsh interface portproxy` rule that forwards your WireGuard address to `127.0.0.1`.
- Adds a restrictive Windows Firewall rule that only allows the remote IP you specify.
- Monitors Chrome and tears everything down (processes, proxy, firewall, temp profile) when you exit.

## Requirements

- Windows 10/11 with PowerShell 5.1+ (the default Windows PowerShell works).
- Administrator privileges (required for `netsh` and firewall operations).
- Google Chrome installed in either `C:\Program Files\Google\Chrome\Application\chrome.exe` or `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`.
- WireGuard interface configured if you plan to use Remote mode.

## Usage

Run PowerShell **as Administrator**, change into the repository directory, and execute:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\chrome-dev-tool-setup.ps1
```

The script will prompt for:

1. **Mode**
   - `Local`: only starts Chrome with DevTools listening on `127.0.0.1:<port>`.
   - `Remote`: also configures the port proxy and firewall rule so a remote host can reach Chrome through your WireGuard IP.
2. **DevTools Port** (default `9229`).
3. **Listen Address** and **Allowed Remote IP** (Remote mode only).

If conflicts are detected (e.g., Chrome already running on the port, existing port-proxy entry, or firewall rule), the script now pauses and asks whether to:

- Proceed and remove the conflicting resources.
- Choose a different port and retry.
- Abort without touching any current sessions.

Selecting **N** (abort) stops the script immediately without closing your existing Chrome windows or tampering with network rules.

During startup you will see four steps (launch Chrome, configure proxy, add firewall rule, verify). When you are done debugging, press `Ctrl+C`; the script will shut everything down gracefully.

### Headless Operation

All prompts can be bypassed by providing parameters:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\chrome-dev-tool-setup.ps1 `
   -Mode Remote `
   -Port 9229 `
   -ListenAddress 172.30.10.54 ` # Your VPN/WireGuard address
   -RemoteIP 172.30.10.53        # Remote dev/client IP allowed through the firewall
```

The defaults already match the manual steps listed in the project description.

## Creating a Desktop Shortcut / Button

You can place a desktop shortcut (or pin it to the taskbar) so Chrome Remote Debugging is one click away.

1. **Create the shortcut**
   1. Right-click the desktop → **New → Shortcut**.
   2. When asked for the item location, paste:
      ```
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File "K:\chrome-remote-profile\chrome-dev-tool-setup.ps1"
      ```
   3. Click **Next**, name it something like `Chrome Remote Debugging`, and finish.
2. **Force the shortcut to run elevated**
   1. Right-click the shortcut → **Properties**.
   2. In the **Shortcut** tab, click **Advanced…**.
   3. Check **Run as administrator** and confirm.
3. **Optional polish**
   - Click **Change Icon…** to pick the Chrome icon (`chrome.exe`) so the shortcut is easy to spot.
   - Drag the shortcut to the taskbar or Start menu to pin it, or assign a keyboard shortcut via **Shortcut key**.
   - You can browse to `chrome.exe` if you want the Chrome icon.

Now double-clicking the shortcut (and accepting the UAC prompt) will launch the script with the correct working directory.

## Troubleshooting Tips

- **Chrome process not detected**: ensure no Group Policy blocks access to Chrome command lines. The script falls back to WMI, but antivirus tools can still interfere.
- **Profile directory will not delete**: Chrome may still be running; wait a few seconds and rerun the script—the cleanup logic retries deletion three times.
- **Port already in use / existing proxy**: You will be prompted to remove the conflicts, pick another port, or abort without changes.

Feel free to adjust the default port, listen address, or remote IP inside `chrome-dev-tool-setup.ps1` if your environment changes.
