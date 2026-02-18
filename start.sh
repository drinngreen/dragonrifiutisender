#!/bin/bash

# Debug: List files to ensure Bridge is there
echo "Checking Bridge files in /app/bridge-service/bin:"
ls -la /app/bridge-service/bin

# Start Bridge in background
echo "Starting .NET Bridge Service..."
cd /app/bridge-service/bin
# Run in background but keep stdout visible
dotnet RentriBridgeService.dll > /app/bridge.log 2>&1 &
BRIDGE_PID=$!

# Wait for bridge to be ready loop
echo "Waiting for Bridge to listen on 8765..."
for i in {1..30}; do
    if curl -s http://localhost:8765/health > /dev/null || curl -s http://localhost:8765 > /dev/null; then
        echo "Bridge is UP!"
        break
    fi
    echo "Bridge not ready yet... ($i/30)"
    sleep 1
done

# Print bridge logs if it failed
if ! curl -s http://localhost:8765 > /dev/null; then
    echo "WARNING: Bridge might not have started. Logs:"
    cat /app/bridge.log
fi

# Start Node App
echo "Starting Node.js Application..."
cd /app
# Use global tsx directly, assuming src/index.ts is the entry point
tsx src/index.ts &
NODE_PID=$!

# Wait for any process to exit
wait -n

# Exit with status of process that exited first
exit $?
