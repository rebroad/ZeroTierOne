# Windows x64 Cross-Build + Single-File Installer (from Linux)

This workflow builds `zerotier-one_x64.exe` on Linux with MinGW and packages a single installer `.exe` via NSIS.

## Prerequisites (Linux)

- `x86_64-w64-mingw32-gcc`
- `x86_64-w64-mingw32-g++`
- `makensis`

## Build + Package

From repository root:

```bash
tools/windows-cross/build-and-package.sh
```

Output:

- Staged payload: `build/windows-x64/bin/`
- Installer: `build/windows-x64/ZeroTier-One-Cross-x64-Installer.exe`

## What The Installer Does

- Installs binaries to: `C:\Program Files\ZeroTier\One`
- Installs TAP driver files to: `C:\ProgramData\ZeroTier\One`
- Registers service by running:

```text
zerotier-one_x64.exe -I
```

- Starts service: `sc start ZeroTierOneService`

## Silent Install / Uninstall

NSIS supports silent mode with `/S`.

Install silently:

```powershell
.\ZeroTier-One-Cross-x64-Installer.exe /S
```

Uninstall silently:

```powershell
"C:\Program Files\ZeroTier\One\Uninstall.exe" /S
```

## Remote Install via Cygwin SSHD

Copy installer, then run over SSH as an Administrator account:

```bash
scp build/windows-x64/ZeroTier-One-Cross-x64-Installer.exe admin@winhost:/cygdrive/c/Temp/
ssh admin@winhost 'cmd /c "C:\\Temp\\ZeroTier-One-Cross-x64-Installer.exe /S"'
```

Service verification:

```bash
ssh admin@winhost 'cmd /c "sc query ZeroTierOneService"'
```

