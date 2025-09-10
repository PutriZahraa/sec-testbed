#!/bin/bash

# Iteration Runner for Custom Security Experiments
set -euo pipefail

# Check arguments
if [ $# -ne 1 ]; then
    echo "Usage: $0 <number_of_iterations>"
    echo "Example: $0 10"
    exit 1
fi

ITERATIONS=$1
RESULTS_FILE="experiment_results_$(date +"%Y%m%d_%H%M%S").txt"

# Validate input
if ! [[ "$ITERATIONS" =~ ^[0-9]+$ ]] || [ "$ITERATIONS" -lt 1 ]; then
    echo "❌ Error: Number of iterations must be a positive integer"
    exit 1
fi

# Check if testbed is running
if ! docker compose ps | grep -q "sec_monitor.*Up"; then
    echo "❌ Error: Security testbed is not running"
    echo "Please start it first with: ./start_testbed.sh"
    exit 1
fi

echo "==============================================="
echo "🔄 Running $ITERATIONS Custom Security Experiments"
echo "==============================================="
echo "Results will be saved to: $RESULTS_FILE"
echo

# Initialize results file
cat > "$RESULTS_FILE" << EOF
CUSTOM SECURITY EXPERIMENT ITERATIONS
=====================================
Total Iterations: $ITERATIONS
Started: $(date)
=====================================

EOF

# Run iterations
for i in $(seq 1 $ITERATIONS); do
    echo "[$(date +'%H:%M:%S')] 🚀 Starting iteration $i/$ITERATIONS..."
    
    # Add iteration header to results file
    echo "ITERATION $i - $(date)" >> "$RESULTS_FILE"
    echo "===========================================" >> "$RESULTS_FILE"
    
    # Run the experiment and capture output
    if ./run_custom_experiment.sh > temp_output.txt 2>&1; then
        echo "[$(date +'%H:%M:%S')] ✅ Iteration $i completed successfully"
        
        # Extract only the summary section
        sed -n '/📋 EXPERIMENT SUMMARY:/,/Fresh eve\.json ready for next experiment/p' temp_output.txt >> "$RESULTS_FILE"
        
        # Add separator
        echo "" >> "$RESULTS_FILE"
        echo "-------------------------------------------" >> "$RESULTS_FILE"
        echo "" >> "$RESULTS_FILE"
        
    else
        echo "[$(date +'%H:%M:%S')] ❌ Iteration $i failed"
        echo "ITERATION $i - FAILED" >> "$RESULTS_FILE"
        echo "Error occurred during execution" >> "$RESULTS_FILE"
        echo "" >> "$RESULTS_FILE"
        echo "-------------------------------------------" >> "$RESULTS_FILE"
        echo "" >> "$RESULTS_FILE"
    fi
    
    # Clean up temp file
    rm -f temp_output.txt
    
    # Wait between iterations (except for the last one)
    if [ $i -lt $ITERATIONS ]; then
        echo "[$(date +'%H:%M:%S')] ⏳ Waiting 10 seconds before next iteration..."
        sleep 10
    fi
done

# Add completion summary to results file
cat >> "$RESULTS_FILE" << EOF

ITERATION SUMMARY
=================
Total Iterations: $ITERATIONS
Completed: $(date)
Results File: $RESULTS_FILE

EOF

echo
echo "==============================================="
echo "🎉 All $ITERATIONS iterations completed!"
echo "==============================================="
echo "Results saved to: $RESULTS_FILE"
echo
echo "To view results:"
echo "  cat $RESULTS_FILE"
echo
echo "To analyze results:"
echo "  grep -A20 'EXPERIMENT SUMMARY' $RESULTS_FILE"
echo
