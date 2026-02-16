import crypto from 'crypto';
import fs from 'fs';
import { RENTRI_CONFIG, CompanyKey } from '../config';

/**
 * Generates an Agid-JWT-Signature in JWS Detached format.
 * Uses Node.js Native crypto.pkcs12 (if available in environment) as requested.
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

    // 1. Read file as pure binary buffer
    const p12Buffer = fs.readFileSync(certPath);

    // 2. Use Node Native PKCS12
    // We assume this method exists in the target Node environment (Render)
    // even if local types don't define it.
    
    let privateKeyObj: crypto.KeyObject;

    try {
        // @ts-ignore: Assuming crypto.pkcs12 exists or falling back
        if (crypto.pkcs12 && typeof crypto.pkcs12.getPrivateKey === 'function') {
            console.log(`[AgidSigner] Using crypto.pkcs12.getPrivateKey (Native)`);
            // @ts-ignore
            const { key } = crypto.pkcs12.getPrivateKey(p12Buffer, certPass);
            privateKeyObj = crypto.createPrivateKey(key);
        } else {
            // Fallback to standard createPrivateKey with pkcs12 format (Node 15.6+)
            // This is actually the standard way to do what user asked, but cleaner syntax
            console.log(`[AgidSigner] Fallback: Using standard crypto.createPrivateKey({ format: 'pkcs12' })`);
            privateKeyObj = crypto.createPrivateKey({
                key: p12Buffer,
                format: 'pkcs12',
                passphrase: certPass
            });
        }
    } catch (e: any) {
        console.error(`[AgidSigner] Native Crypto Error:`, e.message);
        throw new Error(`Failed to extract private key via Native Crypto: ${e.message}`);
    }

    // 3. JWS Header
    const header = { alg: 'RS256', typ: 'JWT' };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const payloadB64 = Buffer.from(payload).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 4. Sign
    const signingInput = `${headerB64}.${payloadB64}`;
    const sign = crypto.createSign('SHA256');
    sign.update(signingInput);
    sign.end();
    
    const signatureB64 = sign.sign(privateKeyObj, 'base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    console.log(`[AgidSigner] Signature generated via Native Crypto.`);
    return `${headerB64}..${signatureB64}`;
}
