# Remote Linux builds and installs

The remote build targets assume that the repository has been synchronized to
its external `.build` tree. Run them from that build tree so generated objects,
Rust artifacts, and container output remain outside the source checkout.

Build for a compatible x86-64 or ARM64 Linux host and install over SSH:

```sh
make remote-install REMOTE_HOST=user@host
```

The target builds a Ubuntu 22.04 builder image, builds ZeroTier One inside the
container, checks the remote CPU architecture and glibc baseline, stages the
binary and installer under `/var/tmp/zerotier-remote-install`, then runs the
installer with `sudo`. The installer checks the binary architecture and shared
library dependencies before replacing the installed executable. It keeps a
`.prev` copy of the prior executable and restores it if restarting the service
fails. Set `REMOTE_STAGE_DIR`, `REMOTE_SSH`, `REMOTE_SCP`, `REMOTE_SUDO`, or
`REMOTE_BUILD_DIR` to override defaults.

The Ubuntu builder enables MaxMind support when linking the binary, so the
target needs its `libmaxminddb` runtime package. The installer refuses to
replace the current binary if a required shared library is missing. If a local
GeoLite2 database is readable and the target has none, the installer stages
that file under `/var/lib/geoip`.

When replacing an existing installation, the staged installer keeps a backup
and arms its rollback-on-next-boot systemd service. After confirming the new
service is stable, remove `/var/lib/zerotier-one/.rollback-on-reboot` on the
remote host to disarm that rollback.

For a 32-bit ARMv7 Raspberry Pi, run:

```sh
tools/pi-install.sh user@pi
```

This uses the Pi builder image and the same remote preflight and installer.
Docker must support `linux/arm/v7` emulation. Set `CONTAINER_RUNTIME=podman` to
use Podman, or override `PI_BUILD_DIR` and `DOCKER_PI_BASE_IMAGE` as needed.

`docker-build-clean` removes the cached Ubuntu builder image. It does not
remove build outputs.
