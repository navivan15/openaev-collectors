#!/bin/bash
# Start the lab Splunk container and wait until it is healthy.
#
#   bash lab_up.sh /path/to/splunk-lab.env
#
# The container listens on this machine only (127.0.0.1): 8000 web, 8089 management,
# 18088 event collector. The env file holds the lab passwords and stays OUTSIDE the
# repository; see validation-ants/docs/SETUP.md for what goes in it.
# Starting the container means accepting Splunk's licence terms (set in the env file).
set -u
NAME=oaev-lab-splunk
ENVF="${1:-${OAEV_LAB_ENV:-$HOME/.oaev-lab/splunk-lab.env}}"
[ -f "$ENVF" ] || { echo "no env file at $ENVF"; exit 1; }
docker pull -q splunk/splunk:latest >/dev/null || { echo "pull failed"; exit 1; }
if ! docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
  docker run -d --name "$NAME" --hostname "$NAME" \
    -p 127.0.0.1:8000:8000 -p 127.0.0.1:8089:8089 -p 127.0.0.1:18088:8088 \
    --env-file "$ENVF" splunk/splunk:latest >/dev/null || { echo "run failed"; exit 1; }
else
  docker start "$NAME" >/dev/null
fi
state=unknown
health=unknown
for i in $(seq 1 100); do
  state=$(docker inspect -f '{{.State.Status}}' "$NAME")
  health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$NAME")
  [ "$state" != "running" ] && break
  [ "$health" = "healthy" ] && break
  sleep 6
done
echo "state=$state health=$health"
docker ps --filter "name=$NAME" --format '{{.Status}} {{.Ports}}'
# The last log lines, without anything that names a password or a token.
docker logs --tail 15 "$NAME" 2>&1 | grep -vi 'password\|token' | cut -c1-180
