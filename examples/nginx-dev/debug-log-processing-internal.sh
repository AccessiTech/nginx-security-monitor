#!/bin/bash
# This script is designed to be run INSIDE the container
# Add a test entry to access.log
echo "192.168.65.1 - - [$(date +"%d/%b/%Y:%H:%M:%S %z")] \"GET /debug-test?id=1%27+OR+1%3D1+--+ HTTP/1.1\" 404 153 \"-\" \"DEBUG-SQL-INJECTION-TEST\" \"-\"" >> /var/log/nginx/access.log

# Wait 3 seconds for processing
echo "Added test entry to access.log, waiting 3 seconds..."
sleep 3

# Check if entry was logged
echo "Checking access log for entry..."
grep "DEBUG-SQL-INJECTION-TEST" /var/log/nginx/access.log

# Check if monitor processed it
echo "Checking monitor log for processing..."
tail -50 /var/log/nginx-security-monitor.log
