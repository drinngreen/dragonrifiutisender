import crypto from 'crypto';
import fs from 'fs';
import { execSync } from 'child_process';
import { RENTRI_CONFIG, CompanyKey } from '../config';

/**
 * Generates an Agid-JWT-Signature in JWS Detached format.
 * Uses OpenSSL CLI to extract Private Key from PFX, bypassing Node/Crypto PFX limitations.
 */
export function signAgidPayload(payload: string, company: CompanyKey): string {
    const config = RENTRI_CONFIG[company];
    if (!config) throw new Error(`Config not found for company: ${company}`);

    const certPath = config.certPath;
    const certPass = company === 'global' 
        ? process.env.RENTRI_CERT_PASS_GLOBAL 
        : process.env.RENTRI_CERT_PASS_MULTY;

    if (!fs.existsSync(certPath)) {
        throw new Error(`Certificate not found at: ${certPath}`);
    }
    
    if (!certPass) {
        throw new Error(`Certificate password missing for ${company}. Set RENTRI_CERT_PASS_${company.toUpperCase()}`);
    }

    // 1. Extract Private Key using OpenSSL CLI (Robust Method)
    // We create temporary files in /tmp/ (Render standard)
    const uniqueId = Date.now().toString() + Math.random().toString().slice(2,6);
    const tempPassPath = `/tmp/pass_${uniqueId}.txt`;
    const tempKeyPath = `/tmp/key_${uniqueId}.pem`;

    let privateKeyPem: string;

    try {
        console.log(`[AgidSigner] Extracting Private Key via OpenSSL CLI from ${certPath}`);
        
        // Write password to temp file (secure)
        fs.writeFileSync(tempPassPath, certPass);

        // Run OpenSSL to extract private key without encryption (-nodes)
        // Command: openssl pkcs12 -in P12 -nocerts -out KEY -nodes -passin file:PASS
        // Use -legacy if needed for older P12 algorithms (RC2/3DES) on OpenSSL 3
        const legacyFlag = process.version.startsWith('v17') || process.version.startsWith('v18') || process.version.startsWith('v20') ? '-legacy' : '';
        
        execSync(`openssl pkcs12 -in "${certPath}" -nocerts -out "${tempKeyPath}" -nodes -passin file:"${tempPassPath}" ${legacyFlag}`);
        
        // Read the extracted PEM key
        privateKeyPem = fs.readFileSync(tempKeyPath, 'utf8');

    } catch (e: any) {
        console.error(`[AgidSigner] OpenSSL Error:`, e.message);
        // Try without -legacy if it failed (maybe older OpenSSL version on Render?)
        try {
             if (e.message.includes("legacy")) {
                 console.log("[AgidSigner] Retrying without -legacy flag...");
                 execSync(`openssl pkcs12 -in "${certPath}" -nocerts -out "${tempKeyPath}" -nodes -passin file:"${tempPassPath}"`);
                 privateKeyPem = fs.readFileSync(tempKeyPath, 'utf8');
             } else {
                 throw e;
             }
        } catch (retryErr: any) {
             throw new Error(`Failed to extract private key via OpenSSL: ${retryErr.message}`);
        }
    } finally {
        // Clean up temp files
        if (fs.existsSync(tempPassPath)) fs.unlinkSync(tempPassPath);
        if (fs.existsSync(tempKeyPath)) fs.unlinkSync(tempKeyPath);
    }

    // 2. Import into Node Crypto (Standard PEM is universally accepted)
    const privateKey = crypto.createPrivateKey(privateKeyPem);

    // 3. Create JWS Detached Header (Minimal)
    const header = {
        alg: 'RS256',
        typ: 'JWT'
    };
    
    // Base64URL encode header
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 4. Base64URL encode payload (for signature calculation only)
    const payloadB64 = Buffer.from(payload).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 5. Create Signature
    const signingInput = `${headerB64}.${payloadB64}`;
    
    const sign = crypto.createSign('SHA256');
    sign.update(signingInput);
    sign.end();
    
    const signatureB64 = sign.sign(privateKey, 'base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 6. Return JWS Detached Format
    console.log(`[AgidSigner] Signature generated successfully via OpenSSL.`);
    return `${headerB64}..${signatureB64}`;
}
