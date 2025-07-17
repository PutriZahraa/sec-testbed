# Security Testbed AI Agent Instructions

## Project Overview
This is a Docker-based security testbed for generating labeled cybersecurity datasets. The system consists of 4 containers connected through OpenVSwitch with port mirroring for comprehensive traffic analysis and ML-ready dataset generation.

## Architecture & Core Components

### Container Network (100.64.0.0/24)
- **Attacker** (100.64.0.10): Generates attack traffic with timing markers
- **Victim** (100.64.0.20:3000): OWASP Juice Shop vulnerable web application
- **Monitor** (100.64.0.30): Suricata 8.0.0 IDS with ML feature extraction
- **Switch** (host network): OpenVSwitch with port mirroring to monitor

### Key Data Flows
1. **Attack Generation**: `attacker/attack_scenarios/attack_tools.sh` → timing markers in `/logs/attack_markers.log`
2. **Traffic Capture**: Switch mirrors all traffic → Monitor captures via Suricata → `data/captures/eve.json`
3. **ML Processing**: `monitor/scripts/ml_dataset_generator.py` correlates eve.json with attack markers → `data/analysis/ml_dataset_*.csv`

## Critical Development Workflows

### Starting the Testbed
```bash
./start_testbed.sh  # Comprehensive startup with OVS initialization
# NOT: docker compose up -d  # Missing OVS setup
```

### Running Attacks (Essential for Dataset Generation)
```bash
docker exec -it sec_attacker ./attack_scenarios/attack_tools.sh
# Generates coordinated attacks with proper timing correlation
```

### ML Model Integration
- Place trained models in `monitor/models/detection_model.pkl`
- Use `monitor/mode2_ml_detector.py` for Mode 2 (ML-only) detection testing
- Mount models directory: `./monitor/scripts:/scripts` (already configured)

### Dataset Generation Commands
```bash
# Generate ML dataset with attack correlation
docker exec sec_monitor python3 /scripts/ml_dataset_generator.py

# Test ML model effectiveness
docker exec sec_monitor python3 /mode2_ml_detector.py /captures/eve.json

# Extract features for training
docker exec sec_monitor python3 /scripts/ml_demo.py
```

## Project-Specific Patterns

### Attack Correlation System
- `signal_attack()` function creates timing markers: `ATTACK_MARKER|type|START/END|timestamp`
- ML dataset generator correlates eve.json events with these markers for supervised learning
- Never modify timing logic without understanding correlation impact

### Container Privilege Requirements
- **Switch**: `privileged: true`, `network_mode: host` (required for OVS)
- **Monitor**: `NET_ADMIN`, `NET_RAW`, `privileged: true` (required for packet capture)
- **Attacker**: `NET_ADMIN`, `SYS_ADMIN` (required for attack tools)
- **Victim**: `NET_ADMIN` only (minimal privileges)

### Volume Mount Patterns
```yaml
# Standard data mounts (already configured)
- ./data/captures:/captures      # Suricata logs
- ./data/analysis:/analysis      # ML datasets  
- ./monitor/scripts:/scripts     # ML processing scripts
- ./data/attacker_logs:/logs     # Attack timing markers
```

## Security & Isolation Requirements

### Critical Safety Checks
- **NEVER** expose to public internet - always use isolated networks
- **NEVER** use production data - intentionally vulnerable services only
- **ALWAYS** run in VMs or isolated container hosts
- **ALWAYS** verify isolation with `docker network inspect sec-testbed`

### Dataset Labels & Features
- Binary classification: `0=benign`, `1=malicious` (correlated with attack markers)
- Attack types: `nmap_scan`, `sql_injection`, `brute_force`, `ddos`, `directory_enum`
- ML features: Flow duration, packet counts, protocol analysis (see `monitor/models/README.md`)

## Debugging & Troubleshooting

### Common Issues
- **OVS not working**: Check `docker logs sec_switch` and `ovs-vsctl show`
- **No traffic capture**: Verify port mirroring with `ovs-vsctl list Mirror`
- **ML model errors**: Check sklearn version compatibility (container uses 1.4.1.post1)
- **Attack correlation missing**: Verify attack markers in `/logs/attack_markers.log`

### Status Commands
```bash
./utils/status.sh           # Comprehensive system status
docker exec sec_switch ovs-vsctl show  # OVS bridge status
docker exec sec_monitor tail -f /captures/eve.json  # Live traffic
```

### Cleanup & Maintenance
```bash
./utils/cleanup.sh 3        # Keep last 3 days of data
./utils/reset.sh            # Complete reset
./utils/archive.sh          # Archive current datasets
```

## Integration Points

### ML Pipeline Integration
- Suricata eve.json → `ml_dataset_generator.py` → CSV datasets → RandomForest training
- Use `monitor/scripts/realtime_detector.py` for live ML inference
- Feature extraction optimized for RandomForest but compatible with other ML algorithms

### Attack Scenario Extensions
- Add new attacks to `attacker/attack_scenarios/attack_tools.sh`
- Always use `signal_attack()` for proper correlation
- Target port 3000 (Juice Shop) for web application attacks
- Test connectivity with `check_connectivity()` function

Remember: This is an educational tool requiring responsible use in completely isolated environments.
