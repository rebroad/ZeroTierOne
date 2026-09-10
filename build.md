# ZeroTier Build and Project Information

## Build and Platform Notes

### Basic Build Instructions

To build on Mac and Linux just type `make`. On FreeBSD and OpenBSD `gmake` (GNU make) is required and can be installed from packages or ports. For Windows there is a Visual Studio solution in `windows/`.

### Platform Requirements

#### Mac
- Xcode command line tools for macOS 10.13 or newer are required.
- Rust for x86_64 and ARM64 targets *if SSO is enabled in the build*.

#### Linux
- The minimum compiler versions required are GCC/G++ 8.x or CLANG/CLANG++ 5.x.
- Linux makefiles automatically detect and prefer clang/clang++ if present as it produces smaller and slightly faster binaries in most cases. You can override by supplying CC and CXX variables on the make command line.
- Rust for x86_64 and ARM64 targets *if SSO is enabled in the build*.

#### Windows
- Visual Studio 2022 on Windows 10 or newer.
- Rust for x86_64 and ARM64 targets *if SSO is enabled in the build*.

### Linux Cross-Build for Windows (x64)

The repository also supports building a Windows x64 installer from Linux using MinGW + NSIS.

Prerequisites:
- `x86_64-w64-mingw32-gcc`
- `x86_64-w64-mingw32-g++`
- `makensis`

Primary Make targets:
- `make windows` runs Windows cross-build + packaging
- `make windows-install` copies the installer to a remote Windows host and installs it with elevation

Output installer:
- `build/windows-x64/ZeroTier-One-x64-Installer.exe`

Remote install via Cygwin SSH with elevation (runs installer as `SYSTEM` using Scheduled Tasks):
- `make REMOTE_HOST=<host> windows-install`
- Installer deploys into the existing ZeroTier service binary directory when present (for example `C:\ProgramData\ZeroTier\One` or `C:\Program Files (x86)\ZeroTier\One`), restarts `ZeroTierOneService`, and includes a temporary failsafe auto-start + rollback path to reduce outage risk during replacement.
- During `windows-install`, if the remote host lacks a GeoLite2 database and the local build host has one under `/var/lib/geoip` or `/usr/share/GeoIP`, it is staged to the remote host and copied into `C:\ProgramData\ZeroTier\One`.

Defaults:
- `REMOTE_HOST=vicco`
- `WINDOWS_OUT_DIR=build/windows-x64`
- `WINDOWS_INSTALLER=$(WINDOWS_OUT_DIR)/ZeroTier-One-x64-Installer.exe`

For detailed usage and troubleshooting, see `doc/windows-cross-installer.md`.

### Raspberry Pi 3 Install (Linux host via SSH)

Use `make pi-install` to build an ARMv7 binary in a container and install it on a Raspberry Pi host over SSH.

Primary Make target:
- `make pi-install`

Defaults:
- `PI_HOST=pi3`
- `PI_INSTALL_STAGE_DIR=/var/tmp/zerotier-remote-install`
- `DOCKER_PI_BUILD_IMAGE=zerotier-build-pi3`
- `DOCKER_PI_DOCKERFILE=tools/Dockerfile.pi3-builder`
- `DOCKER_PI_BASE_IMAGE=arm32v7/debian:buster` (matches `~/src/node/build-pi3.sh`)

The install flow stages `zerotier-one` and `tools/install-zerotier-staged.sh` to the Pi, then runs the staged installer via `sudo`.

#### FreeBSD
- GNU make is required. Type `gmake` to build.
- `binutils` is required. Type `pkg install binutils` to install.
- Rust for x86_64 and ARM64 targets *if SSO is enabled in the build*.

#### OpenBSD
- There is a limit of four network memberships on OpenBSD as there are only four tap devices (`/dev/tap0` through `/dev/tap3`).
- GNU make is required. Type `gmake` to build.
- Rust for x86_64 and ARM64 targets *if SSO is enabled in the build*.

### Building with CMake (optional)

> **Note:** CMake is an *alternative* build path, offered as a convenience. The official
> builds are still produced by the platform makefiles (above) and the Visual Studio solution
> in `windows/`.

#### Prerequisites

- **CMake** 3.15 or newer.
- The same compiler/toolchain (and Rust, if SSO is enabled) as the makefile build for your
  platform — see *Platform Requirements* above.
- The header-only **OpenTelemetry API** must be present on `CMAKE_PREFIX_PATH`. Populate it
  into `./.deps` by running the bootstrap script once, in its **default** (quick, header-only)
  mode — i.e. *without* `ZT_CONTROLLER_DEPS=1`, which is the heavyweight controller-only path:

  ```bash
  scripts/bootstrap-deps.sh    # default mode: header-only OTel API into ./.deps
  ```

  The script prints the exact `-DCMAKE_PREFIX_PATH` to use when it finishes.

#### Free vs. default (non-free) builds

By default the daemon is built **with the bundled FileDB network controller**, which lives
under `nonfree/` and is "source available" (non-free) — this matches what ships in official
builds (`ZT_NONFREE=ON`). To produce a **purely free** daemon (MPL-2.0 `node/`, `osdep/`,
`service/` only, with no `nonfree/` code compiled or linked), set **`-DZT_NONFREE=OFF`** — or
use one of the `*-free-*` presets, which set it for you.

#### Using presets (recommended)

`cmake --list-presets` shows the presets for your OS. The daemon presets are:

| Preset | Build |
| --- | --- |
| `macos-release` / `linux-release` | Default daemon (**includes** the non-free bundled controller) |
| `macos-free-release` / `linux-free-release` | **Free** daemon (`ZT_NONFREE=OFF`, no non-free code) |
| `macos-debug` / `linux-debug` (and `*-free-debug`) | Debug variants of the above |
| `macos-universal-release` | macOS universal (arm64 + x86_64) daemon |
| `freebsd-release` / `openbsd-release` / `netbsd-release` (and `*-free-release`, `*-debug`) | BSD daemon / free variant |
| `windows-x64-release` (and `windows-x64-free`) | Windows daemon / free variant |

```bash
# Default (non-free) daemon:
cmake --preset macos-release
cmake --build --preset macos-release

# Purely free daemon:
cmake --preset macos-free-release
cmake --build --preset macos-free-release
```

Each preset builds into its own directory, `build-<presetName>/`, so the binary lands at e.g.
`build-macos-free-release/zerotier-one`. (macOS/Linux presets use single-config Unix Makefiles,
so the build type is baked into the preset name — there's no `Release/` subdirectory.)

#### Manual invocation

The equivalent without presets:

```bash
# Default (non-free) daemon — .deps holds the OTel API from bootstrap-deps.sh:
cmake -DCMAKE_PREFIX_PATH="$PWD/.deps" -S . -B build
cmake --build build -j8

# Purely free daemon:
cmake -DZT_NONFREE=OFF -DCMAKE_PREFIX_PATH="$PWD/.deps" -S . -B build
cmake --build build -j8
```

The binary is `build/zerotier-one`. (On macOS, append the Homebrew prefixes to
`CMAKE_PREFIX_PATH` if your dependencies come from Homebrew, as the presets do.)

### Testing

Typing `make selftest` will build a *zerotier-selftest* binary which unit tests various internals and reports on a few aspects of the build environment. It's a good idea to try this on novel platforms or architectures.

## Running ZeroTier

Running *zerotier-one* with `-h` option will show help.

On Linux and BSD, if you built from source, you can start the service with:

    sudo ./zerotier-one -d

On most distributions, macOS, and Windows, the installer will start the service and set it up to start on boot.

A home folder for your system will automatically be created.

The service is controlled via the JSON API, which by default is available at `127.0.0.1:9993`. It also listens on `0.0.0.0:9993` which is only usable if `allowManagementFrom` is properly configured in `local.conf`. We include a *zerotier-cli* command line utility to make API calls for standard things like joining and leaving networks. The *authtoken.secret* file in the home folder contains the secret token for accessing this API. See [service/README.md](service/README.md) for API documentation.

## Directory Structure

### Home Folder Locations

ZeroTier stores its configuration and state files in platform-specific locations:

* **Linux**: `/var/lib/zerotier-one`
* **FreeBSD** / **OpenBSD**: `/var/db/zerotier-one`
* **Mac**: `/Library/Application Support/ZeroTier/One`
* **Windows**: `\ProgramData\ZeroTier\One` (That's the default. The base 'shared app data' folder might be different if Windows is installed with a non-standard drive letter assignment or layout.)

### Project Structure

The repository is organized as follows:

- **node/** - Core ZeroTier networking code
- **osdep/** - Operating system dependent code  
- **service/** - Service implementation and API
- **controller/** - Network controller implementation
- **ext/** - External code included for build convenience (retains original licenses)
- **nonfree/** - Source available (non-free) portions
- **windows/** - Windows-specific Visual Studio solution files

### Build System

The project supports various build targets and platforms:
- Standard build: `make`
- Self-test build: `make selftest`
- Platform-specific requirements:
  - FreeBSD/OpenBSD: Use `gmake` (GNU make)
  - Windows: Visual Studio solution in `windows/`

### License Structure

- **node/**, **osdep/**, **service/**: Licensed under MPL-2.0 (see LICENSE-MPL.txt)
- **nonfree/**: Non-free "source available" code (see nonfree/LICENSE.md)
- **ext/**: External code with original licenses retained
