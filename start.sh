#!/bin/bash

# Ensure we exit on error (mostly)
# set -e 

echo "=== STARTING DEPLOYMENT SCRIPT ==="
echo "Current Directory: $(pwd)"
echo "User: $(whoami)"

# 1. Check if Bridge files exist
echo "Checking Bridge files in /app/bridge-service/bin:"
if [ -f "/app/bridge-service/bin/RentriBridgeService.dll" ]; then
    echo "✅ RentriBridgeService.dll FOUND"
else
    echo "❌ RentriBridgeService.dll NOT FOUND in /app/bridge-service/bin"
    ls -la /app/bridge-service/bin
    exit 1
fi

# 2. Start Bridge in background
echo "Starting .NET Bridge Service..."
cd /app/bridge-service/bin
# Redirect output to a log file AND stdout for visibility
dotnet RentriBridgeService.dll > /app/bridge.log 2>&1 &
BRIDGE_PID=$!
echo "Bridge PID: $BRIDGE_PID"

# 3. Wait for bridge to be ready loop
echo "Waiting for Bridge to listen on 8765..."
MAX_RETRIES=30
for i in $(seq 1 $MAX_RETRIES); do
    # Try localhost first
    if curl -s http://localhost:8765/health > /dev/null || curl -s http://127.0.0.1:8765 > /dev/null; then
        echo "✅ Bridge is UP and listening on port 8765!"
        break
    fi
    
    # Check if process is still running
    if ! kill -0 $BRIDGE_PID 2>/dev/null; then
        echo "❌ Bridge process died unexpectedly!"
        echo "=== BRIDGE LOGS START ==="
        cat /app/bridge.log
        echo "=== BRIDGE LOGS END ==="
        exit 1
    fi
    
    echo "Bridge not ready yet... ($i/$MAX_RETRIES)"
    sleep 1
done

# Final check
if ! curl -s http://localhost:8765 > /dev/null && ! curl -s http://127.0.0.1:8765 > /dev/null; then
    echo "❌ Timeout waiting for Bridge."
    echo "=== BRIDGE LOGS START ==="
    cat /app/bridge.log
    echo "=== BRIDGE LOGS END ==="
    # We exit here because without bridge, the app is useless
    exit 1
fi

# 4. Start Node App
echo "Starting Node.js Application..."
cd /app
# Use global tsx directly, assuming src/index.ts is the entry point
tsx src/index.ts &
NODE_PID=$!

# Wait for any process to exit
wait -n

# Exit with status of process that exited first
exit $?
