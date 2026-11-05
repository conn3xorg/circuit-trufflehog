#!/usr/bin/env sh
# Runs on the host: plants a fake secret, scans through the timer's service,
# and checks the findings name it, leave out the excluded host keys, and that
# the scan wrote nothing outside its results directory. CI pipes it in with
# podman exec.
set -eu
systemctl is-enabled conn3x-trufflehog.timer

# The placeholder webhook from Slack's own documentation: it matches
# TruffleHog's pattern and opens no workspace. It's put together here, so
# the script itself doesn't trip GitHub's push protection.
plant=/opt/conn3x-trufflehog-check
mkdir -p "$plant"
slack=hooks.slack.com
echo "SLACK_WEBHOOK=https://$slack/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX" > "$plant/app.env"
marker=/var/tmp/conn3x-trufflehog-check.marker
touch "$marker"
sleep 1

systemctl start conn3x-trufflehog.service

d=/var/lib/conn3x-trufflehog/latest
cat "$d/summary.txt"
grep -q '"DetectorName":"SlackWebhook"' "$d/findings.json"
grep -q '"file":"/opt/conn3x-trufflehog-check/app.env"' "$d/findings.json"
grep -qx 'SlackWebhook unverified 1' "$d/summary.txt"
if grep -q '/etc/ssh/ssh_host_' "$d/findings.json"; then
  echo "The findings include a host key that exclude_paths leaves out." >&2
  exit 1
fi
[ "$(stat -c %a /var/lib/conn3x-trufflehog)" = 700 ]

changed=$(find / -xdev -type f -newer "$marker" \
  -not -path '/var/lib/conn3x-trufflehog/*' \
  -not -path '/var/log/*' -not -path '/var/lib/rsyslog/*' -not -path '/var/lib/systemd/*' -not -path '/run/*' -not -path '/tmp/*' -not -path '/var/tmp/*')
if [ -n "$changed" ]; then
  echo "The scan changed files on the host:" >&2
  echo "$changed" >&2
  exit 1
fi

rm -rf "$plant" "$marker"
