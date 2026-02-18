#!/bin/bash

# Start Bridge in background
echo "Starting .NET Bridge Service..."
cd /app/bridge-service/bin
dotnet RentriBridgeService.dll &
BRIDGE_PID=$!

# Wait for bridge to be ready (optional check)
sleep 5

# Start Node App
echo "Starting Node.js Application..."
cd /app
npx tsx index_clean.ts &
NODE_PID=$!

# Wait for any process to exit
wait -n

# Exit with status of process that exited first
exit $?
