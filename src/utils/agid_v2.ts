import crypto from 'crypto';
import fs from 'fs';
import { spawnSync } from 'child_process';
import { RENTRI_CONFIG, CompanyKey } from '../config';

/**
 * Generates an Agid-JWT-Signature in JWS Detached format using ES256 algorithm.
 * Uses OpenSSL CLI via spawnSync to robustly extract Private Key from PFX.
 * This handles both modern and legacy P12 algorithms (RC2/3DES) safely.
 */
export function signAgidPayload(payload: string, company: CompanyKey): string {
    const config = RENTRI_CONFIG[company];
    if (!config) throw new Error(`Config not found for company: ${company}`);

    const certPath = config.certPath;
    const certPass = company === 'global' 
        ? process.env.RENTRI_CERT_PASS_GLOBAL 
        : process.env.RENTRI_CERT_PASS_MULTY;

    if (!fs.existsSync(certPath)) throw new Error(`Certificate not found: ${certPath}`);
    if (!certPass) throw new Error(`Password missing for ${company}`);

    // 1. Prepare temporary paths in /tmp (Render compliant)
    const uniqueId = Date.now().toString() + Math.random().toString().slice(2,6);
    const tempP12Path = `/tmp/cert_${uniqueId}.p12`;
    const tempPassPath = `/tmp/pass_${uniqueId}.txt`;
    const tempKeyPath = `/tmp/key_${uniqueId}.pem`;

    let privateKeyPem: string;

    try {
        console.log(`[AgidSigner] Extracting Key via OpenSSL CLI (SpawnSync)`);

        // Copy P12 to temp to avoid permission issues and ensure clean state
        fs.copyFileSync(certPath, tempP12Path);
        
        // Write password to temp file (secure, no shell injection)
        fs.writeFileSync(tempPassPath, certPass);

        // Run OpenSSL: try with -legacy provider first (OpenSSL 3+)
        // openssl pkcs12 -in P12 -nocerts -out KEY -nodes -passin file:PASS -legacy
        let result = spawnSync('openssl', [
            'pkcs12',
            '-in', tempP12Path,
            '-nocerts',
            '-out', tempKeyPath,
            '-nodes',
            '-passin', `file:${tempPassPath}`,
            '-legacy'
        ]);

        if (result.status !== 0) {
            console.log(`[AgidSigner] OpenSSL (Legacy) failed, retrying without -legacy flag...`);
            // Retry without -legacy (for older OpenSSL or non-legacy algorithms)
            result = spawnSync('openssl', [
                'pkcs12',
                '-in', tempP12Path,
                '-nocerts',
                '-out', tempKeyPath,
                '-nodes',
                '-passin', `file:${tempPassPath}`
            ]);
        }

        if (result.status !== 0) {
            const stderr = result.stderr.toString();
            throw new Error(`OpenSSL failed with code ${result.status}: ${stderr}`);
        }

        // Read the extracted PEM key
        if (!fs.existsSync(tempKeyPath)) {
            throw new Error("OpenSSL succeeded but key file was not created.");
        }
        
        privateKeyPem = fs.readFileSync(tempKeyPath, 'utf8');

    } catch (e: any) {
        throw new Error(`Failed to extract private key via OpenSSL: ${e.message}`);
    } finally {
        // Clean up temp files
        if (fs.existsSync(tempP12Path)) fs.unlinkSync(tempP12Path);
        if (fs.existsSync(tempPassPath)) fs.unlinkSync(tempPassPath);
        if (fs.existsSync(tempKeyPath)) fs.unlinkSync(tempKeyPath);
    }

    // 2. Import into Node Crypto (Standard PEM is universally accepted)
    const privateKeyObj = crypto.createPrivateKey(privateKeyPem);

    // 3. JWS Header (ES256 for AgID)
    const header = { alg: 'ES256', typ: 'JWT' };
    
    // Base64URL encode header
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 4. Base64URL encode payload
    const payloadB64 = Buffer.from(payload).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 5. Sign (ES256 - IEEE P1363)
    const signingInput = `${headerB64}.${payloadB64}`;
    
    const signature = crypto.sign("sha256", Buffer.from(signingInput), {
        key: privateKeyObj,
        dsaEncoding: "ieee-p1363", 
    });

    const signatureB64 = signature.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 6. Return JWS Detached Format: header..signature
    console.log(`[AgidSigner] JWS Detached generated via OpenSSL CLI.`);
    return `${headerB64}..${signatureB64}`;
}
