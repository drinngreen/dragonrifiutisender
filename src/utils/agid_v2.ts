import crypto from 'crypto';
import fs from 'fs';
import { spawnSync } from 'child_process';
import { RENTRI_CONFIG, CompanyKey } from '../config';

/**
 * Generates an Agid-JWT-Signature in JWS Detached format using ES256 algorithm.
 * Supports Base64 P12 from Environment Variables to avoid filesystem corruption issues.
 * Uses OpenSSL CLI via spawnSync for robust key extraction.
 */
export function signAgidPayload(payload: string, company: CompanyKey): string {
    const config = RENTRI_CONFIG[company];
    if (!config) throw new Error(`Config not found for company: ${company}`);

    const certPath = config.certPath; // Fallback path
    const certPass = company === 'global' 
        ? process.env.RENTRI_CERT_PASS_GLOBAL 
        : process.env.RENTRI_CERT_PASS_MULTY;

    if (!certPass) throw new Error(`Password missing for ${company}`);

    // 1. Get P12 Content (Try Env Base64 first, then File)
    let p12Buffer: Buffer;
    
    // Check for Base64 Env Var (The robust way)
    const envBase64 = company === 'global' 
        ? process.env.RENTRI_CERT_BASE64_GLOBAL 
        : process.env.RENTRI_CERT_BASE64_MULTY;

    if (envBase64 && envBase64.length > 100) {
        console.log(`[AgidSigner] Using Base64 Certificate from Env Var for ${company}`);
        p12Buffer = Buffer.from(envBase64, 'base64');
    } else {
        // Fallback to file reading
        console.log(`[AgidSigner] Reading P12 from file: ${certPath}`);
        if (!fs.existsSync(certPath)) throw new Error(`Certificate not found at: ${certPath}`);
        p12Buffer = fs.readFileSync(certPath);
    }

    // 2. Prepare temporary paths in /tmp (Render compliant)
    const uniqueId = Date.now().toString() + Math.random().toString().slice(2,6);
    const tempP12Path = `/tmp/cert_${uniqueId}.p12`;
    const tempPassPath = `/tmp/pass_${uniqueId}.txt`;
    const tempKeyPath = `/tmp/key_${uniqueId}.pem`;

    let privateKeyPem: string;

    try {
        // Write buffer to clean temp file (avoids corruption)
        fs.writeFileSync(tempP12Path, p12Buffer);
        fs.writeFileSync(tempPassPath, certPass);

        // Run OpenSSL to extract key
        // Try with -legacy provider first (OpenSSL 3+)
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
            // Log partial output for debugging
            console.error(`[AgidSigner] OpenSSL Stderr: ${stderr}`);
            throw new Error(`OpenSSL failed with code ${result.status}: ${stderr}`);
        }

        // Read extracted PEM key
        if (!fs.existsSync(tempKeyPath)) {
            throw new Error("OpenSSL succeeded but key file was not created.");
        }
        
        privateKeyPem = fs.readFileSync(tempKeyPath, 'utf8');

    } catch (e: any) {
        throw new Error(`Failed to extract private key via OpenSSL: ${e.message}`);
    } finally {
        // Clean up temp files
        try {
            if (fs.existsSync(tempP12Path)) fs.unlinkSync(tempP12Path);
            if (fs.existsSync(tempPassPath)) fs.unlinkSync(tempPassPath);
            if (fs.existsSync(tempKeyPath)) fs.unlinkSync(tempKeyPath);
        } catch (cleanupErr) {
            console.warn(`[AgidSigner] Cleanup warning: ${cleanupErr}`);
        }
    }

    // 3. Import into Node Crypto
    const privateKeyObj = crypto.createPrivateKey(privateKeyPem);

    // 4. JWS Header (ES256 for AgID)
    const header = { alg: 'ES256', typ: 'JWT' };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const payloadB64 = Buffer.from(payload).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 5. Sign (ES256 - IEEE P1363)
    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = crypto.sign("sha256", Buffer.from(signingInput), {
        key: privateKeyObj,
        dsaEncoding: "ieee-p1363", 
    });

    const signatureB64 = signature.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 6. Return JWS Detached Format
    console.log(`[AgidSigner] JWS Detached generated via OpenSSL (Base64/File Source).`);
    return `${headerB64}..${signatureB64}`;
}
