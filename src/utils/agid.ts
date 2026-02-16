import crypto from 'crypto';
import fs from 'fs';
import { RENTRI_CONFIG, CompanyKey } from '../config';

/**
 * Generates an Agid-JWT-Signature in JWS Detached format using ES256 algorithm.
 * Compliant with AgID/RENTRI specifications for Elliptic Curve certificates.
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
    let privateKeyObj: crypto.KeyObject;

    try {
        // Native Node key extraction logic (robust on Render)
        // @ts-ignore
        if (crypto.pkcs12 && typeof crypto.pkcs12.getPrivateKey === 'function') {
            // @ts-ignore
            const { key } = crypto.pkcs12.getPrivateKey(p12Buffer, certPass);
            privateKeyObj = crypto.createPrivateKey(key);
        } else {
            privateKeyObj = crypto.createPrivateKey({
                key: p12Buffer,
                format: 'pkcs12',
                passphrase: certPass
            });
        }
    } catch (e: any) {
        throw new Error(`Failed to extract private key: ${e.message}`);
    }

    // 2. JWS Header (ES256 for AgID)
    const header = { alg: 'ES256', typ: 'JWT' };
    
    // Base64URL encode header
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 3. Base64URL encode payload (for signature calculation only)
    const payloadB64 = Buffer.from(payload).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 4. Sign (ES256 - IEEE P1363)
    // The input to sign is "header.payload"
    const signingInput = `${headerB64}.${payloadB64}`;
    
    // Use crypto.sign convenience method with dsaEncoding option (Node 15+)
    // This is critical for ES256 compliance with JWT standard
    const signature = crypto.sign("sha256", Buffer.from(signingInput), {
        key: privateKeyObj,
        dsaEncoding: "ieee-p1363", 
    });

    const signatureB64 = signature.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 5. Return JWS Detached Format: header..signature
    console.log(`[AgidSigner] JWS Detached generated (ES256 IEEE-P1363).`);
    return `${headerB64}..${signatureB64}`;
}
