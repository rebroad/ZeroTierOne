#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
HOST="${1:-vicco}"
LOCAL_INSTALLER="${2:-$ROOT_DIR/build/windows-x64/ZeroTier-One-Cross-x64-Installer.exe}"
REMOTE_INSTALLER_NAME="ZeroTier-One-Cross-x64-Installer.exe"
REMOTE_INSTALLER_CYG="/cygdrive/c/Temp/${REMOTE_INSTALLER_NAME}"
REMOTE_INSTALLER_WIN='C:\\Temp\\ZeroTier-One-Cross-x64-Installer.exe'
TASK_NAME="ZeroTierOneRemoteInstall"
LOG_PATH_WIN='C:\\Temp\\ZeroTier-One-Cross-install.log'
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15)

if [ ! -f "$LOCAL_INSTALLER" ]; then
  echo "Installer not found: $LOCAL_INSTALLER" >&2
  echo "Build it first with: tools/windows-cross/build-and-package.sh" >&2
  exit 1
fi

echo "[1/5] Upload installer to $HOST"
scp "${SSH_OPTS[@]}" "$LOCAL_INSTALLER" "$HOST:~/$REMOTE_INSTALLER_NAME"

echo "[2/5] Copy installer to $REMOTE_INSTALLER_CYG"
ssh "${SSH_OPTS[@]}" "$HOST" "cp -f ~/$REMOTE_INSTALLER_NAME $REMOTE_INSTALLER_CYG"

echo "[3/5] Schedule elevated SYSTEM install task"
ssh "${SSH_OPTS[@]}" "$HOST" "cmd /c \"schtasks /Delete /TN $TASK_NAME /F >NUL 2>&1\""
ssh "${SSH_OPTS[@]}" "$HOST" "cmd /c \"schtasks /Create /TN $TASK_NAME /SC ONCE /ST 00:00 /RL HIGHEST /RU SYSTEM /TR \\\"$REMOTE_INSTALLER_WIN /S\\\" /F\""
ssh "${SSH_OPTS[@]}" "$HOST" "cmd /c \"schtasks /Run /TN $TASK_NAME\""

echo "[4/5] Poll task status"
for _ in $(seq 1 30); do
  STATUS_LINE="$(ssh "${SSH_OPTS[@]}" "$HOST" "cmd /c \"schtasks /Query /TN $TASK_NAME /V /FO LIST | findstr /B /C:\"Status:\"\"" || true)"
  RESULT_LINE="$(ssh "${SSH_OPTS[@]}" "$HOST" "cmd /c \"schtasks /Query /TN $TASK_NAME /V /FO LIST | findstr /B /C:\"Last Run Result:\"\"" || true)"
  echo "$STATUS_LINE"
  echo "$RESULT_LINE"
  if echo "$STATUS_LINE" | grep -qi "Ready"; then
    break
  fi
  sleep 2
done

echo "[5/5] Fetch installer log and service status"
ssh "${SSH_OPTS[@]}" "$HOST" "cmd /c \"if exist $LOG_PATH_WIN (type $LOG_PATH_WIN) else (echo Installer log not found at $LOG_PATH_WIN)\""
ssh "${SSH_OPTS[@]}" "$HOST" "cmd /c \"sc query ZeroTierOneService\""

echo "Remote install attempt complete on $HOST"
