# Xelite

**Xelite** is a VPN client for **Windows 10 Mobile**, similar to Happ / Incy on Android and iOS.
It works on Windows 10 Mobile ARM phones (build 15063 or later).

* Runs **Xray-core v26.2.6**, the last release with an official Windows ARM32 build
* Metro UI: a pivot with home, servers, subscriptions and settings, a square connect tile, and the phone's own theme and accent colour
* **Multiple subscriptions**, each with **any number of servers**, plus a "manual" group for pasted links
* **auto** entry for every subscription with 2+ servers: Xray's balancer picks the best server and switches automatically
  * *least ping*: `observatory` probes every server once a minute and uses the fastest
  * *least load*: `burstObservatory` samples each server 3 times per minute and picks among the stable, low-latency ones
* Subscriptions from **Happ / Incy / Remnawave / Marzban / 3x-ui** panels:
  * base64 or plain link lists, or Xray JSON (one config or an array, the format panels serve to Happ)
  * the `subscription-userinfo` header (traffic used / total / expiry) and `profile-title`
  * import wrappers such as `happ://add/https://…`, `incy://…https://…` and `v2rayng://install-config?url=…`
* **HWID device limit** (Remnawave, also used by Happ / Incy): sends `x-hwid`, `x-device-os`, `x-ver-os` and `x-device-model`
  * the ID is stable per device and survives reinstalling the app; it can be viewed, copied, replaced (for example with an old device's ID) or turned off in settings
  * "device limit reached" and "device ID required" are reported clearly, based on the panel's `x-hwid-*` response headers
* **Config editor**: long-press a server → edit opens its Xray outbound as JSON. Edits of subscription servers are saved as a copy in "manual", so updates don't overwrite them
* Configs from panels written for newer Xray are adapted to v26.2.6: the core carries a backport of the XHTTP seq/session placement fix (`core/patches`), and the app rewrites `uplinkDataPlacement: "auto"` and `uplinkChunkSize` ranges
* Share links: `vless://` (REALITY, Vision, XHTTP, VLESS encryption), `vmess://`, `trojan://`, `ss://` (incl. 2022), `hysteria2://` (salamander obfs)
* Transports: raw/tcp (+http header), ws, grpc, httpupgrade, xhttp, hysteria
* System-wide VPN (all apps), DNS through the tunnel, LAN bypass, optional QUIC block, TCP ping, log viewer

## How it works

```
 apps ──► Windows VPN interface ──► VpnBackgroundTask (Xelite.VpnTask, C#)
                                        │  every IP packet = 1 UDP datagram
                                        ▼  127.0.0.1:<port>
                                    xelite-core.exe  (Go, ARMv7)
                                    ├─ gVisor TCP/IP stack (turns packets back into TCP/UDP flows)
                                    └─ Xray-core ──► your server
```

* `core/` is the Go engine: Xray-core plus a gVisor netstack bridge (`bridge.go`). Captured flows are
  dispatched into Xray with the inbound tag `tun` and sniffing (http/tls/quic, route-only).
* `app/Xelite.VpnTask/` is the UWP VPN plug-in (`IVpnPlugIn`). The VPN channel's outer transport is
  a `DatagramSocket` connected to the core. `Encapsulate` passes packets through unchanged and
  `Decapsulate` injects the core's replies.
* `app/Xelite/` is the phone UI (Pivot: servers / subscriptions / settings), the link parser and the config builder.
* The server's IP is resolved before connecting and excluded from the tunnel, so Xray's own traffic
  doesn't loop back into the VPN.

Why a separate `.exe` instead of a DLL: Go dropped `windows/arm` (32-bit) in 1.26. Go 1.25 still has it,
but it is a "broken" port without cgo, so `-buildmode=c-shared` is unavailable. The plug-in therefore
launches `xelite-core.exe` from the app package with `CreateProcessW`.

## Build

### 1. The Go core (macOS, Linux or Windows)

```sh
./build-core.sh          # -> build/ARM/xelite-core.exe, build/x64/xelite-core.exe
```

This needs Go **1.25.x**. If it isn't on PATH, the script downloads Go 1.25.14 into `.toolchain/`.

### 2. The app package (Windows only)

You need Visual Studio 2019 or 2022 with the **Universal Windows Platform development** workload,
including ARM support, and **Windows 10 SDK 10.0.19041.0**.

```powershell
.\build.ps1                  # Release|ARM  -> dist\Xelite_1.7.1.0_ARM_Test\Xelite_1.7.1.0_ARM.appx
.\build.ps1 -Platform x64    # PC build, to test the whole flow on a Windows 10/11 desktop
```

`build.ps1` creates a self-signed certificate `CN=Xelite` (`app\Xelite\Xelite_TemporaryKey.pfx`,
public part in `dist\Xelite.cer`) on the first run.

There is also a GitHub Actions workflow (`.github/workflows/build.yml`) that builds the ARM `.appx` on `windows-2022`.

## Install on the phone

1. On the phone: **Settings → Update & security → For developers → Developer mode**, and enable
   **Device discovery** and **Device Portal**.
2. On a PC, open the Device Portal address the phone shows (e.g. `https://192.168.1.50`). Go to
   **Apps → Install app**, then pick:
   * the `.appx` from `dist\...\Xelite_1.7.1.0_ARM.appx`
   * the dependencies from `dist\...\Dependencies\ARM\` (`Microsoft.NET.Native.Framework.2.2`,
     `Microsoft.NET.Native.Runtime.2.2`, `Microsoft.VCLibs.140.00`)
   * the certificate `dist\Xelite.cer`, if the portal asks for it
3. Alternatively use `WinAppDeployCmd.exe install -file Xelite_1.7.1.0_ARM.appx -ip <phone ip>`
   from the Windows 10 SDK.

## Use

1. **+** adds a subscription URL. **Paste** imports an http(s) subscription URL or one or more share links from the clipboard.
2. Tap a server to select it, then tap the round button to connect. The first time, Windows asks
   you to allow the "Xelite" VPN profile.
3. **ping** measures TCP latency to every server (only while disconnected).
4. **⋯ → show log** shows the app, VPN plug-in and Xray logs. Check it first if a connection fails. **⋯ → reset VPN profile** recreates the system VPN profile.

The VPN profile also appears in **Settings → Network & Wi-Fi → VPN** and reconnects with the last chosen server.

## Notes and limitations

* **Not yet tested on a real device.** The Go engine is tested on macOS: TCP and UDP through the bridge, a full
  VLESS chain, and both balancer modes with one dead and one live server. Every generated config shape loads in Xray.
  The C# compiles against the Windows 10 SDK metadata. The XAML and the `.appx` itself have to be built on Windows.
* The Go runtime and Xray do run on Windows 10 Mobile: users report the official `Xray-windows-arm32-v7a`
  build working. v26.2.6 is the last release with that build, and it is the version Xelite uses, with the same Go 1.25 toolchain.
* The biggest risk is `CreateProcessW` from the VPN background task on Windows 10 Mobile. If the log
  shows `CreateProcess failed, error 5`, the OS is blocking child processes for sideloaded apps on that
  build. The fallback would be loading the Go image in-process with a manual PE loader.
* IPv4 only inside the tunnel (IPv6 traffic is not captured).
* `allowInsecure` was removed from Xray v26, so links that rely on it need `pcs=<cert sha256>` instead.
* `happ://crypt…` links are encrypted with Happ's private key and only open in Happ. Ask the provider for the plain `https://` subscription URL.
* For JSON subscriptions, only the proxy outbound of each config is used. The config's own routing rules and `dialerProxy` chains are dropped.
* An auto entry balances between at most 32 servers, the first 32 of the subscription.
* The app shows which server auto mode picked only in the Xray log (log level info).
