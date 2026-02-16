import crypto from 'crypto';
import fs from 'fs';
import { RENTRI_CONFIG, CompanyKey } from '../config';

/**
 * Generates an Agid-JWT-Signature in JWS Detached format using ES256 algorithm.
 * Uses native crypto.pkcs12.getPrivateKey (assumed to be available in Render's Node env)
 * to extract private key without using temporary files or node-forge.
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

    // 2. Extract Key using Native PKCS12
    // We assume crypto.pkcs12 exists. If not, this will crash (but user requested this specifically).
    
    // @ts-ignore
    if (!crypto.pkcs12 || typeof crypto.pkcs12.getPrivateKey !== 'function') {
        throw new Error("crypto.pkcs12 is not available in this Node.js version. Upgrade Node or use a polyfill.");
    }

    // @ts-ignore
    const { key } = crypto.pkcs12.getPrivateKey(p12Buffer, certPass);

    if (!key) throw new Error("Failed to extract private key from P12.");

    // 3. Create Key Object (The key is already decrypted)
    const privateKeyObj = crypto.createPrivateKey(key);

    // 4. JWS Header (ES256 for AgID)
    const header = { alg: 'ES256', typ: 'JWT' };
    
    // Base64URL encode header
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 5. Base64URL encode payload
    const payloadB64 = Buffer.from(payload).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 6. Sign (ES256 - IEEE P1363)
    const signingInput = `${headerB64}.${payloadB64}`;
    
    // Use crypto.sign convenience method with dsaEncoding option (Node 15+)
    const signature = crypto.sign("sha256", Buffer.from(signingInput), {
        key: privateKeyObj,
        dsaEncoding: "ieee-p1363", 
    });

    const signatureB64 = signature.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 7. Return JWS Detached Format: header..signature
    console.log(`[AgidSigner] JWS Detached generated (ES256 IEEE-P1363) via Native PKCS12.`);
    return `${headerB64}..${signatureB64}`;
}
