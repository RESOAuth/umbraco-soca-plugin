#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
runtime="${CONTAINER_RUNTIME:-podman}"
image="localhost/umbraco-soca-test:latest"
name="soca-umbraco-$(date +%s)-$$"
cleanup() { "$runtime" rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
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
  if [ "$attempt" = 120 ]; then "$runtime" logs "$name"; exit 1; fi
  sleep 1
done
status="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/umbraco/management/api/v1/soca")"
[ "$status" = 401 ]
"$runtime" logs "$name" | rg 'SOCA_HOST_CHECKS:'
printf 'Native Umbraco backoffice HTTP 200; protected management API HTTP 401. No provider login attempted.\n'
