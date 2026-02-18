import { spawn, spawnSync } from 'child_process';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

// Define __dirname for ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let bridgeProcess: any = null;

// Helper to write sync status for RentriService to check
function updateStatus(msg: string) {
    try {
        fs.appendFileSync('/app/bridge_status.txt', `${new Date().toISOString()} ${msg}\n`);
    } catch (e) {
        // Ignore write errors in dev/local
    }
}

export function startBridge() {
    console.log('[BridgeStarter] Initializing C# Bridge Service...');
    updateStatus('STARTING');

    // 0. Verify Dotnet
    try {
        const check = spawnSync('dotnet', ['--info']);
        if (check.error) {
            console.error('[BridgeStarter] ❌ `dotnet` command not found or failed:', check.error.message);
            updateStatus('DOTNET_MISSING');
            return;
        }
        console.log('[BridgeStarter] `dotnet` command is available.');
    } catch (e: any) {
        console.error('[BridgeStarter] ❌ Failed to check dotnet:', e.message);
    }

    // 1. Define Paths
    // In Docker: /app/bridge-service/bin/RentriBridgeService.dll
    // Local: ../bridge-service/bin/RentriBridgeService.dll (relative to src)
    const possibleDllPaths = [
        '/app/bridge-service/bin/RentriBridgeService.dll',
        path.resolve(__dirname, '../../bridge-service/bin/RentriBridgeService.dll'),
        path.resolve(__dirname, '../bridge-service/bin/RentriBridgeService.dll'),
        path.join(process.cwd(), 'bridge-service/bin/RentriBridgeService.dll')
    ];

    let dllPath: string | undefined;
    for (const p of possibleDllPaths) {
        if (fs.existsSync(p)) {
            dllPath = p;
            break;
        }
    }

    if (!dllPath) {
        console.error('[BridgeStarter] ❌ CRITICAL: RentriBridgeService.dll NOT FOUND!');
        console.error('[BridgeStarter] Checked paths:', possibleDllPaths);
        updateStatus('DLL_NOT_FOUND');
        // We don't exit process here to allow Node API to still run (e.g. for health checks)
        return;
    }

    console.log(`[BridgeStarter] ✅ Found DLL at: ${dllPath}`);
    updateStatus(`DLL_FOUND: ${dllPath}`);
    const bridgeDir = path.dirname(dllPath);

    // 2. Copy Certificates
    // We need to copy .p12 files from src/certs to bridgeDir
    // Since this file is in src/, ../src/certs is just ./certs
    const certsDir = path.resolve(__dirname, 'certs'); // src/certs
    
    if (fs.existsSync(certsDir)) {
        console.log(`[BridgeStarter] Copying certificates from ${certsDir} to ${bridgeDir}...`);
        try {
            const files = fs.readdirSync(certsDir);
            for (const file of files) {
                if (file.endsWith('.p12')) {
                    const src = path.join(certsDir, file);
                    const dest = path.join(bridgeDir, file);
                    fs.copyFileSync(src, dest);
                    console.log(`[BridgeStarter] 📋 Copied ${file}`);
                }
            }
        } catch (e: any) {
            console.error(`[BridgeStarter] ⚠️ Failed to copy certificates: ${e.message}`);
        }
    } else {
        console.warn(`[BridgeStarter] ⚠️ Certs directory not found at ${certsDir}`);
    }

    // 3. Spawn Process
    console.log('[BridgeStarter] Spawning dotnet process...');
    
    // Ensure we are in the bridge directory so it finds the certs
    const options = {
        cwd: bridgeDir,
        env: process.env, // Pass through environment variables
        stdio: 'pipe' as const
    };

    bridgeProcess = spawn('dotnet', ['RentriBridgeService.dll'], options);
    updateStatus('SPAWNED');

    if (bridgeProcess.stdout) {
        bridgeProcess.stdout.on('data', (data: Buffer) => {
            // Log bridge output with a prefix so we can distinguish it
            const lines = data.toString().trim().split('\n');
            lines.forEach((line: string) => console.log(`[Bridge] ${line}`));
        });
    }

    if (bridgeProcess.stderr) {
        bridgeProcess.stderr.on('data', (data: Buffer) => {
            console.error(`[Bridge ERR] ${data.toString().trim()}`);
        });
    }

    bridgeProcess.on('close', (code: number) => {
        console.log(`[BridgeStarter] Bridge process exited with code ${code}`);
        updateStatus(`EXITED: ${code}`);
        // Optional: Restart logic could go here
    });

    bridgeProcess.on('error', (err: Error) => {
        console.error(`[BridgeStarter] Failed to start bridge process: ${err.message}`);
        updateStatus(`ERROR: ${err.message}`);
    });

    if (bridgeProcess.pid) {
        console.log('[BridgeStarter] Bridge process spawned (PID: ' + bridgeProcess.pid + ')');
    }
}

// Handle cleanup
process.on('exit', () => {
    if (bridgeProcess) {
        bridgeProcess.kill();
    }
});
