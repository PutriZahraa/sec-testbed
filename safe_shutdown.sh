#!/bin/bash
# Safe shutdown script with rule persistence

echo "=== Security Testbed Safe Shutdown ==="
echo "$(date): Performing safe shutdown with rule backup"

# Function to backup current rules
backup_current_rules() {
    echo "Backing up current rules from running container..."
    
    # Create backup directory if it doesn't exist
    mkdir -p ./monitor_backup
    
    # Check if monitor container is running
    if docker ps | grep -q sec_monitor; then
        echo "✓ Monitor container is running, backing up rules..."
        
        # Backup the current working rules
        docker exec sec_monitor bash -c "cat /var/lib/suricata/rules/suricata.rules" > ./monitor_backup/suricata.rules 2>/dev/null || echo "⚠ Could not backup main rules file"
        
        # Backup official ET rules if they exist
        docker exec sec_monitor bash -c "cat /var/lib/suricata/rules/official/emerging-web_client.rules" > ./monitor_backup/emerging-web_client.rules 2>/dev/null || echo "⚠ Could not backup client rules"
        docker exec sec_monitor bash -c "cat /var/lib/suricata/rules/official/emerging-web_server.rules" > ./monitor_backup/emerging-web_server.rules 2>/dev/null || echo "⚠ Could not backup server rules"
        
        # Backup setup script
        docker exec sec_monitor bash -c "cat /scripts/setup_official_rules.sh" > ./monitor_backup/setup_official_rules.sh 2>/dev/null || echo "⚠ Could not backup setup script"
        
        echo "✓ Rules backed up to ./monitor_backup/"
        echo "  Files saved:"
        ls -la ./monitor_backup/
        
    else
        echo "⚠ Monitor container is not running, skipping backup"
    fi
}

# Function to safely stop containers
safe_stop_containers() {
    echo "Stopping containers safely..."
    
    # Stop in correct order (dependencies first)
    echo "Stopping monitor container..."
    docker stop sec_monitor 2>/dev/null || echo "Monitor already stopped"
    
    echo "Stopping victim container..."
    docker stop sec_victim 2>/dev/null || echo "Victim already stopped"
    
    echo "Stopping attacker container..."
    docker stop sec_attacker 2>/dev/null || echo "Attacker already stopped"
    
    echo "Stopping switch container..."
    docker stop sec_switch 2>/dev/null || echo "Switch already stopped"
    
    echo "✓ All containers stopped"
}

# Main execution
echo "Step 1: Backing up current rules..."
backup_current_rules

echo "Step 2: Safely stopping containers..."
safe_stop_containers

echo "Step 3: Removing containers..."
docker compose down

echo "✓ Safe shutdown completed!"
echo ""
echo "📁 Rules are preserved in: ./monitor_backup/"
echo "🔄 Next startup will use persistent rules automatically"
echo ""
echo "To restart with persistent rules:"
echo "  ./start_testbed.sh"
echo ""
echo "Backup contents:"
ls -la ./monitor_backup/ 2>/dev/null || echo "No backup directory found"
