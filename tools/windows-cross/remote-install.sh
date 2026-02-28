#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
HOST="${1:-vicco}"
LOCAL_INSTALLER="${2:-$ROOT_DIR/build/windows-x64/ZeroTier-One-x64-Installer.exe}"
PAYLOAD_DIR="$(dirname "$LOCAL_INSTALLER")/bin"
TASK_NAME="ZeroTierOneRemoteInstall"
REMOTE_TEMP_CYG="/cygdrive/c/Temp"
REMOTE_RUNNER_WIN='C:\\Temp\\ZeroTier-One-install-runner.cmd'
RUNNER_LOG_WIN='C:\\Temp\\ZeroTier-One-install-runner.log'
RUNNER_NAME='ZeroTier-One-install-runner.cmd'
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15)

required=(
  "$PAYLOAD_DIR/zerotier-one_x64.exe"
  "$PAYLOAD_DIR/zerotier-cli.bat"
  "$PAYLOAD_DIR/zerotier-idtool.bat"
  "$PAYLOAD_DIR/zttap300.inf"
  "$PAYLOAD_DIR/zttap300.sys"
  "$PAYLOAD_DIR/zttap300.cat"
)

for f in "${required[@]}"; do
  if [ ! -f "$f" ]; then
    echo "Missing payload file: $f" >&2
    echo "Run: make windows" >&2
    exit 1
  fi
done
local_exe_sha="$(sha256sum "$PAYLOAD_DIR/zerotier-one_x64.exe" | awk '{print $1}')"

local_mmdb=""
local_mmdb_mtime=0
for candidate in \
  /var/lib/geoip/GeoLite2-Country.mmdb \
  /usr/share/GeoIP/GeoLite2-Country.mmdb \
  /var/lib/geoip/GeoLite2-City.mmdb \
  /usr/share/GeoIP/GeoLite2-City.mmdb; do
  if [ -r "$candidate" ]; then
    candidate_mtime="$(stat -c %Y "$candidate" 2>/dev/null || echo 0)"
    if [ "$candidate_mtime" -gt "$local_mmdb_mtime" ]; then
      local_mmdb="$candidate"
      local_mmdb_mtime="$candidate_mtime"
    fi
  fi
done

remote_has_geoip="$(ssh "${SSH_OPTS[@]}" "$HOST" 'set -e; usable=0; for p in \
  /cygdrive/c/ProgramData/ZeroTier/One/GeoLite2-Country.mmdb \
  /cygdrive/c/ProgramData/ZeroTier/One/GeoLite2-City.mmdb; do \
    if [ -r "$p" ]; then usable=1; break; fi; \
  done; echo "$usable"' | tr -d '\r' | tail -n1 || true)"

stage_mmdb=""
if [ "${remote_has_geoip:-0}" = "1" ]; then
  echo "Remote GeoIP DB: usable GeoLite2 database already present"
elif [ -n "$local_mmdb" ]; then
  stage_mmdb="$local_mmdb"
  echo "Remote GeoIP DB: missing; will stage local $stage_mmdb"
else
  echo "Remote GeoIP DB: missing and no local GeoLite2 DB available to stage"
fi

mmdb_basename=""
if [ -n "$stage_mmdb" ]; then
  mmdb_basename="$(basename "$stage_mmdb")"
fi

svc_qc="$(ssh "${SSH_OPTS[@]}" "$HOST" 'cmd /c "sc qc ZeroTierOneService"' 2>/dev/null || true)"
svc_bin="$(printf '%s\n' "$svc_qc" | tr -d '\r' | sed -n 's/.*BINARY_PATH_NAME[[:space:]]*:[[:space:]]*//p' | head -n1)"
svc_exe=""
install_dir=""

if [ -n "$svc_bin" ]; then
  if [[ "$svc_bin" == \"* ]]; then
    svc_exe="${svc_bin#\"}"
    svc_exe="${svc_exe%%\"*}"
  else
    svc_exe="${svc_bin%% *}"
  fi
  if [ -n "$svc_exe" ] && [[ "$svc_exe" == *\\* ]]; then
    install_dir="${svc_exe%\\*}"
  fi
fi

if [ -z "$install_dir" ]; then
  has_x86="$(ssh "${SSH_OPTS[@]}" "$HOST" 'cmd /c "if exist \"C:\\Program Files (x86)\\ZeroTier\\One\\zerotier-one_x64.exe\" (echo 1) else (echo 0)"' | tr -d '\r' | tail -n1 || true)"
  if [ "$has_x86" = "1" ]; then
    install_dir='C:\Program Files (x86)\ZeroTier\One'
  else
    install_dir='C:\Program Files\ZeroTier\One'
  fi
fi

echo "Using remote install dir: $install_dir"

runner_local="$(mktemp)"
cleanup() {
  rm -f "$runner_local"
}
trap cleanup EXIT

cat > "$runner_local" <<RUNNER
@echo off
setlocal EnableExtensions

set "LOG=C:\\Temp\\ZeroTier-One-install-runner.log"
set "INSTALL_DIR=$install_dir"
set "MMDB_BASENAME=$mmdb_basename"
set "FAILSAFE_TASK=ZeroTierOneFailsafeStart"
del "%LOG%" >NUL 2>&1

echo [info] starting install runner > "%LOG%"
echo [info] install_dir=%INSTALL_DIR% >> "%LOG%"

if not exist "C:\\Temp\\zerotier-one_x64.exe" (
  echo [error] missing C:\\Temp\\zerotier-one_x64.exe >> "%LOG%"
  goto :fail
)

echo [info] preflight new binary >> "%LOG%"
"C:\\Temp\\zerotier-one_x64.exe" -v >> "%LOG%" 2>&1
if errorlevel 1 goto :fail

echo [info] arming failsafe restart task >> "%LOG%"
schtasks /Delete /TN "%FAILSAFE_TASK%" /F >> "%LOG%" 2>&1
schtasks /Create /TN "%FAILSAFE_TASK%" /SC ONCE /ST 00:00 /RL HIGHEST /RU SYSTEM /TR "cmd /c ping -n 120 127.0.0.1 ^>NUL ^& sc start ZeroTierOneService" /F >> "%LOG%" 2>&1
if errorlevel 1 goto :fail
schtasks /Run /TN "%FAILSAFE_TASK%" >> "%LOG%" 2>&1

echo [info] stopping service >> "%LOG%"
sc stop ZeroTierOneService >> "%LOG%" 2>&1
for /L %%I in (1,1,45) do (
  sc query ZeroTierOneService | findstr /C:"STATE" | findstr /C:"STOPPED" >NUL 2>&1
  if not errorlevel 1 goto :stopped
  ping -n 2 127.0.0.1 >NUL
)

echo [error] service did not stop in time >> "%LOG%"
goto :rollback

:stopped
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "C:\\ProgramData\\ZeroTier\\One" mkdir "C:\\ProgramData\\ZeroTier\\One"

echo [info] staging files >> "%LOG%"
copy /Y C:\\Temp\\zerotier-one_x64.exe "%INSTALL_DIR%\\zerotier-one_x64.new.exe" >> "%LOG%" 2>&1
if errorlevel 1 goto :rollback
"%INSTALL_DIR%\\zerotier-one_x64.new.exe" -v >> "%LOG%" 2>&1
if errorlevel 1 goto :rollback

copy /Y C:\\Temp\\zerotier-cli.bat "%INSTALL_DIR%\\zerotier-cli.bat" >> "%LOG%" 2>&1
if errorlevel 1 goto :rollback
copy /Y C:\\Temp\\zerotier-idtool.bat "%INSTALL_DIR%\\zerotier-idtool.bat" >> "%LOG%" 2>&1
if errorlevel 1 goto :rollback
copy /Y C:\\Temp\\zttap300.inf "C:\\ProgramData\\ZeroTier\\One\\zttap300.inf" >> "%LOG%" 2>&1
if errorlevel 1 goto :rollback
copy /Y C:\\Temp\\zttap300.sys "C:\\ProgramData\\ZeroTier\\One\\zttap300.sys" >> "%LOG%" 2>&1
if errorlevel 1 goto :rollback
copy /Y C:\\Temp\\zttap300.cat "C:\\ProgramData\\ZeroTier\\One\\zttap300.cat" >> "%LOG%" 2>&1
if errorlevel 1 goto :rollback
if not "%MMDB_BASENAME%"=="" (
  if exist "C:\\Temp\\%MMDB_BASENAME%" (
    echo [info] staging geoip database %MMDB_BASENAME% >> "%LOG%"
    copy /Y "C:\\Temp\\%MMDB_BASENAME%" "C:\\ProgramData\\ZeroTier\\One\\%MMDB_BASENAME%" >> "%LOG%" 2>&1
    if errorlevel 1 goto :rollback
  ) else (
    echo [warn] mmdb file not found in C:\\Temp\\%MMDB_BASENAME% >> "%LOG%"
  )
)

if exist "%INSTALL_DIR%\\zerotier-one_x64.old.exe" del /F /Q "%INSTALL_DIR%\\zerotier-one_x64.old.exe" >> "%LOG%" 2>&1
if exist "%INSTALL_DIR%\\zerotier-one_x64.exe" move /Y "%INSTALL_DIR%\\zerotier-one_x64.exe" "%INSTALL_DIR%\\zerotier-one_x64.old.exe" >> "%LOG%" 2>&1
if errorlevel 1 goto :rollback
move /Y "%INSTALL_DIR%\\zerotier-one_x64.new.exe" "%INSTALL_DIR%\\zerotier-one_x64.exe" >> "%LOG%" 2>&1
if errorlevel 1 goto :rollback

echo [info] configuring service path >> "%LOG%"
sc config ZeroTierOneService binPath= "\"%INSTALL_DIR%\\zerotier-one_x64.exe\"" >> "%LOG%" 2>&1
"%INSTALL_DIR%\\zerotier-one_x64.exe" -I >> "%LOG%" 2>&1

echo [info] starting service >> "%LOG%"
sc start ZeroTierOneService >> "%LOG%" 2>&1
if errorlevel 1 goto :rollback

for /L %%I in (1,1,45) do (
  sc query ZeroTierOneService | findstr /C:"STATE" | findstr /C:"RUNNING" >NUL 2>&1
  if not errorlevel 1 goto :running
  ping -n 2 127.0.0.1 >NUL
)

echo [error] service did not reach RUNNING >> "%LOG%"
goto :rollback

:running
echo [info] version check >> "%LOG%"
"%INSTALL_DIR%\\zerotier-one_x64.exe" -v >> "%LOG%" 2>&1
schtasks /Delete /TN "%FAILSAFE_TASK%" /F >> "%LOG%" 2>&1
if exist "%INSTALL_DIR%\\zerotier-one_x64.old.exe" del /F /Q "%INSTALL_DIR%\\zerotier-one_x64.old.exe" >> "%LOG%" 2>&1

echo install_exit=0 >> "%LOG%"
exit /b 0

:rollback
echo [warn] rollback path entered >> "%LOG%"
if exist "%INSTALL_DIR%\\zerotier-one_x64.new.exe" del /F /Q "%INSTALL_DIR%\\zerotier-one_x64.new.exe" >> "%LOG%" 2>&1
if exist "%INSTALL_DIR%\\zerotier-one_x64.old.exe" (
  if exist "%INSTALL_DIR%\\zerotier-one_x64.exe" del /F /Q "%INSTALL_DIR%\\zerotier-one_x64.exe" >> "%LOG%" 2>&1
  move /Y "%INSTALL_DIR%\\zerotier-one_x64.old.exe" "%INSTALL_DIR%\\zerotier-one_x64.exe" >> "%LOG%" 2>&1
)
sc start ZeroTierOneService >> "%LOG%" 2>&1
echo install_exit=1 >> "%LOG%"
exit /b 1

:fail
echo install_exit=1 >> "%LOG%"
exit /b 1
RUNNER

echo "[1/6] Upload payload files to $HOST home"
for f in "${required[@]}"; do
  scp "${SSH_OPTS[@]}" "$f" "$HOST:~/$(basename "$f")"
done
if [ -n "$stage_mmdb" ]; then
  scp "${SSH_OPTS[@]}" "$stage_mmdb" "$HOST:~/$(basename "$stage_mmdb")"
fi
scp "${SSH_OPTS[@]}" "$runner_local" "$HOST:~/$(basename "$runner_local").cmd"
remote_runner_home="~/$(basename "$runner_local").cmd"

echo "[2/6] Copy payload files into C:\\Temp"
ssh "${SSH_OPTS[@]}" "$HOST" "mkdir -p '$REMOTE_TEMP_CYG'"
for f in "${required[@]}"; do
  bn="$(basename "$f")"
  ssh "${SSH_OPTS[@]}" "$HOST" "cp -f ~/$bn '$REMOTE_TEMP_CYG/$bn'"
done
if [ -n "$stage_mmdb" ]; then
  mmdb_bn="$(basename "$stage_mmdb")"
  ssh "${SSH_OPTS[@]}" "$HOST" "cp -f ~/$mmdb_bn '$REMOTE_TEMP_CYG/$mmdb_bn'"
fi
ssh "${SSH_OPTS[@]}" "$HOST" "cp -f $remote_runner_home '$REMOTE_TEMP_CYG/$RUNNER_NAME'"

echo "[3/6] Schedule elevated task"
ssh "${SSH_OPTS[@]}" "$HOST" "cmd /c \"del /F /Q $RUNNER_LOG_WIN >NUL 2>&1\""
ssh "${SSH_OPTS[@]}" "$HOST" "cmd /c \"icacls $REMOTE_RUNNER_WIN /reset >NUL & icacls $REMOTE_RUNNER_WIN /inheritance:e /grant *S-1-5-18:(RX) /grant *S-1-5-32-544:(F) >NUL\""
ssh "${SSH_OPTS[@]}" "$HOST" "cmd /c \"schtasks /Delete /TN $TASK_NAME /F >NUL 2>&1\"" || true
ssh "${SSH_OPTS[@]}" "$HOST" "cmd /c \"schtasks /Create /TN $TASK_NAME /SC ONCE /ST 00:00 /RL HIGHEST /RU SYSTEM /TR $REMOTE_RUNNER_WIN /F\""
ssh "${SSH_OPTS[@]}" "$HOST" "cmd /c \"schtasks /Run /TN $TASK_NAME\""

echo "[4/6] Poll task status"
task_result=""
ready_seen=0
queued_seen=0
for _ in $(seq 1 60); do
  TASK_INFO="$(ssh "${SSH_OPTS[@]}" "$HOST" "cmd /c \"schtasks /Query /TN $TASK_NAME /V /FO LIST\"" || true)"
  STATUS_LINE="$(printf '%s\n' "$TASK_INFO" | tr -d '\r' | grep -i '^Status:' || true)"
  RESULT_LINE="$(printf '%s\n' "$TASK_INFO" | tr -d '\r' | grep -i '^Last Result:' || true)"
  echo "$STATUS_LINE"
  echo "$RESULT_LINE"
  task_result="$(printf '%s\n' "$RESULT_LINE" | sed -n 's/^Last Result:[[:space:]]*//Ip' | xargs || true)"
  if echo "$STATUS_LINE" | grep -qi "Ready"; then
    ready_seen=1
    break
  fi
  if echo "$STATUS_LINE" | grep -qi "Queued"; then
    queued_seen=$((queued_seen + 1))
    if [ "$queued_seen" -ge 10 ]; then
      break
    fi
  fi
  sleep 2
done

if [ "$ready_seen" -ne 1 ]; then
  echo "[4/6] Task did not reach Ready, running runner directly as fallback"
  if ! timeout 300 ssh "${SSH_OPTS[@]}" "$HOST" "cmd /c \"$REMOTE_RUNNER_WIN\""; then
    echo "Fallback direct runner execution failed or timed out" >&2
    exit 1
  fi
fi

echo "[5/6] Fetch runner log and service status"
runner_log="$(ssh "${SSH_OPTS[@]}" "$HOST" "cmd /c \"if exist $RUNNER_LOG_WIN (type $RUNNER_LOG_WIN) else (echo Runner log not found at $RUNNER_LOG_WIN)\"" | tr -d '\r')"
printf '%s\n' "$runner_log"
ssh "${SSH_OPTS[@]}" "$HOST" "cmd /c \"sc query ZeroTierOneService\""
ssh "${SSH_OPTS[@]}" "$HOST" "cmd /c \"sc qc ZeroTierOneService\""

echo "[6/6] Verify version from Cygwin ssh environment"
ssh "${SSH_OPTS[@]}" "$HOST" "set -e; type -a zerotier-cli || true; zerotier-cli -v || true"

if ! printf '%s\n' "$runner_log" | grep -q 'install_exit=0'; then
  echo "Remote runner did not report success" >&2
  exit 1
fi
if [ -n "$task_result" ] && [[ "$task_result" =~ ^[0-9]+$ ]] && [ "$task_result" != "0" ]; then
  echo "Scheduled task reported Last Result=$task_result" >&2
  exit 1
fi
remote_exe_sha="$(ssh "${SSH_OPTS[@]}" "$HOST" 'set -e; svc="$(cmd /c \"sc qc ZeroTierOneService\" | tr -d \"\r\" | sed -n \"s/.*BINARY_PATH_NAME[[:space:]]*:[[:space:]]*//p\" | head -n1)"; svc="${svc#\"}"; svc="${svc%\"}"; d="${svc:0:1}"; rest="${svc:2}"; rest="${rest//\\\\//}"; p="/cygdrive/${d,,}/${rest}"; sha256sum "$p" | awk "{print \$1}"' | tr -d '\r' | tail -n1)"
if [ "$remote_exe_sha" != "$local_exe_sha" ]; then
  echo "Installed binary hash mismatch (local=$local_exe_sha remote=$remote_exe_sha)" >&2
  exit 1
fi

echo "Remote install complete on $HOST"
