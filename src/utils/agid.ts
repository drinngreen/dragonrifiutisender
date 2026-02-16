import crypto from 'crypto';
import fs from 'fs';
import { RENTRI_CONFIG, CompanyKey } from '../config';

/**
 * Generates an Agid-JWT-Signature in JWS Detached format.
 * Format: header..signature (payload is omitted)
 * The signature is calculated over "header.payload"
 */
export function signAgidPayload(payload: string, company: CompanyKey): string {
    const config = RENTRI_CONFIG[company];
    if (!config) throw new Error(`Config not found for company: ${company}`);

    const certPath = config.certPath;
    
    // Read password from environment variables
    const certPass = company === 'global' 
        ? process.env.RENTRI_CERT_PASS_GLOBAL 
        : process.env.RENTRI_CERT_PASS_MULTY;

    if (!fs.existsSync(certPath)) {
        throw new Error(`Certificate not found at: ${certPath}`);
    }
    
    if (!certPass) {
        throw new Error(`Certificate password missing for ${company}. Set RENTRI_CERT_PASS_${company.toUpperCase()}`);
    }

    // 1. Extract Private Key from PFX
    // Node.js crypto supports reading key from PFX with passphrase directly
    let privateKey: crypto.KeyObject;
    try {
        const pfxBuffer = fs.readFileSync(certPath);
        privateKey = crypto.createPrivateKey({
            key: pfxBuffer,
            format: 'pfx',
            passphrase: certPass
        });
    } catch (e: any) {
        throw new Error(`Failed to read private key from PFX: ${e.message}`);
    }

    // 2. Create Minimal JWS Header
    // IMPORTANT: Do NOT include 'x5c' to avoid "Header too long" error from RENTRI
    const header = {
        alg: 'RS256',
        typ: 'JWT'
    };
    
    // Base64URL encode header
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 3. Base64URL encode payload (for signature calculation only)
    const payloadB64 = Buffer.from(payload).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 4. Create Signature
    // Input for signing: header.payload
    const signingInput = `${headerB64}.${payloadB64}`;
    
    const sign = crypto.createSign('SHA256');
    sign.update(signingInput);
    sign.end();
    
    const signatureB64 = sign.sign(privateKey, 'base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 5. Return JWS Detached Format: header..signature
    console.log(`[AgidSigner] Generated signature for payload length ${payload.length}`);
    return `${headerB64}..${signatureB64}`;
}
