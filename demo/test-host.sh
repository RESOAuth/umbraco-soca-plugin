#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
runtime="${CONTAINER_RUNTIME:-podman}"
image="localhost/umbraco-soca-test:latest"
name="soca-umbraco-$(date +%s)-$$"
cleanup() { "$runtime" rm -f "$name" "$name-recovery" >/dev/null 2>&1 || true; }
trap cleanup EXIT
wait_marker() {
  local container="$1" marker="$2" logs
  for attempt in $(seq 1 120); do
    logs="$("$runtime" logs "$container" 2>&1)"
    if [[ "$logs" == *"$marker"* ]]; then printf '%s\n' "$marker"; return; fi
    if [ "$("$runtime" inspect --format '{{.State.Running}}' "$container")" != true ]; then
      printf '%s\n' "$logs"; return 1
    fi
    sleep 1
  done
  printf '%s\n' "$logs"; return 1
}
"$runtime" build -t "$image" -f Containerfile .
admin_password="$(openssl rand -hex 24)"
"$runtime" run -d --name "$name" -p 127.0.0.1::8080 \
  -e SOCA_HOST_CHECKS=1 \
  -e Umbraco__CMS__Unattended__InstallUnattended=true \
  -e Umbraco__CMS__Unattended__UnattendedUserName=LocalDemoAdministrator \
  -e Umbraco__CMS__Unattended__UnattendedUserEmail=admin@example.com \
  -e "Umbraco__CMS__Unattended__UnattendedUserPassword=$admin_password" "$image" >/dev/null
port="$("$runtime" port "$name" 8080/tcp | sed -n 's/127.0.0.1://p')"
for attempt in $(seq 1 120); do
  status="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/umbraco/" || true)"
  if [ "$status" = 200 ]; then break; fi
  if [ "$("$runtime" inspect --format '{{.State.Running}}' "$name")" != true ]; then "$runtime" logs "$name"; exit 1; fi
  if [ "$attempt" = 120 ]; then "$runtime" logs "$name"; exit 1; fi
  sleep 1
done
status="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/umbraco/management/api/v1/soca")"
[ "$status" = 401 ]
wait_marker "$name" "SOCA_HOST_CHECKS:"
printf 'Native Umbraco backoffice HTTP 200; protected management API HTTP 401. No provider login attempted.\n'

# A missing signing key under global emergency disable must preserve local recovery.
"$runtime" run -d --name "$name-recovery" -p 127.0.0.1::8080 \
  -e SOCA_EMERGENCY_DISABLED=1 \
  -e SOCA_HOST_CHECKS=1 \
  -e Soca__Profiles__0__Name=recovery \
  -e Soca__Profiles__0__PrivateKeyFile=/missing/emergency-key.pem \
  -e Umbraco__CMS__Unattended__InstallUnattended=true \
  -e Umbraco__CMS__Unattended__UnattendedUserName=LocalDemoAdministrator \
  -e Umbraco__CMS__Unattended__UnattendedUserEmail=admin@example.com \
  -e "Umbraco__CMS__Unattended__UnattendedUserPassword=$admin_password" "$image" >/dev/null
port="$("$runtime" port "$name-recovery" 8080/tcp | sed -n 's/127.0.0.1://p')"
for attempt in $(seq 1 120); do
  status="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/umbraco/" || true)"
  if [ "$status" = 200 ]; then break; fi
  if [ "$("$runtime" inspect --format '{{.State.Running}}' "$name-recovery")" != true ]; then "$runtime" logs "$name-recovery"; exit 1; fi
  if [ "$attempt" = 120 ]; then "$runtime" logs "$name-recovery"; exit 1; fi
  sleep 1
done
status="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/umbraco/management/api/v1/soca")"
[ "$status" = 401 ]
status="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/soca/recovery/backoffice/metadata")"
[ "$status" = 404 ]
wait_marker "$name-recovery" "SOCA_EMERGENCY_CHECKS:"
wait_marker "$name-recovery" "SOCA_HOST_CHECKS:"
printf 'Emergency recovery with a missing signing key: native backoffice HTTP 200, protected API HTTP 401, disabled metadata HTTP 404.\n'
