import crypto from 'crypto';
import fs from 'fs';
import { RENTRI_CONFIG, CompanyKey } from '../config';

/**
 * Generates an Agid-JWT-Signature in JWS Detached format using ES256 algorithm.
 * Uses crypto.createPrivateKey with 'p12' format (Render Node compatibility).
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

    // 1. Read P12 file
    const p12Buffer = fs.readFileSync(certPath);

    // 2. Extract Key using 'p12' format
    let privateKey: crypto.KeyObject;
    try {
        privateKey = crypto.createPrivateKey({
            key: p12Buffer,
            format: 'p12', // Using 'p12' as requested (Node alias for pkcs12)
            passphrase: certPass
        });
    } catch (e: any) {
        throw new Error(`Failed to extract private key with format 'p12': ${e.message}`);
    }

    // 3. JWS Header (ES256 for AgID)
    const header = { alg: 'ES256', typ: 'JWT' };
    
    // Base64URL encode header
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 4. Base64URL encode payload
    const payloadB64 = Buffer.from(payload).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 5. Sign (ES256 - IEEE P1363)
    const signingInput = `${headerB64}.${payloadB64}`;
    
    // Use crypto.sign convenience method with dsaEncoding option (Node 15+)
    const signature = crypto.sign("sha256", Buffer.from(signingInput), {
        key: privateKey,
        dsaEncoding: "ieee-p1363", 
    });

    const signatureB64 = signature.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 6. Return JWS Detached Format: header..signature
    console.log(`[AgidSigner] JWS Detached generated via 'p12' format.`);
    return `${headerB64}..${signatureB64}`;
}
