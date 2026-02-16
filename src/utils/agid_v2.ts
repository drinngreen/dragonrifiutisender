import forge from 'node-forge';
import crypto from 'crypto';
import fs from 'fs';
import { RENTRI_CONFIG, CompanyKey } from '../config';

/**
 * Generates an Agid-JWT-Signature in JWS Detached format using ES256 algorithm.
 * Uses node-forge with BINARY string conversion to robustly extract private key.
 * This bypasses Node.js native crypto limitations with P12 encoding.
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

    // 1. Read file as Buffer
    const p12Buffer = fs.readFileSync(certPath);

    // 2. Convert to binary string for Forge (CRITICAL FIX for binary data)
    // Node.js 'binary' encoding is essentially Latin-1, which preserves bytes as char codes
    const p12Binary = p12Buffer.toString('binary');
    
    // 3. Parse ASN.1
    const p12Asn1 = forge.asn1.fromDer(p12Binary);
    
    // 4. Decrypt P12
    let p12: forge.pkcs12.Pkcs12P12;
    try {
        p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, certPass);
    } catch (e: any) {
        throw new Error(`Forge P12 Decryption Failed: ${e.message}`);
    }

    // 5. Extract Private Key Bag
    // Try ShroudedKeyBag first (most common for PFX)
    let bag = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0];
    
    if (!bag) {
        // Fallback to plain KeyBag
        bag = p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag]?.[0];
    }

    if (!bag) {
        throw new Error("Private key bag not found in P12 via Forge");
    }

    // 6. Convert to PEM (Node.js native format)
    // This gives us a standard PKCS#8 or PKCS#1 PEM string
    const privateKeyPem = forge.pki.privateKeyToPem(bag.key);
    
    // 7. Create Key Object
    const privateKey = crypto.createPrivateKey(privateKeyPem);

    // 8. JWS Header (ES256)
    const header = { alg: 'ES256', typ: 'JWT' };
    
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const payloadB64 = Buffer.from(payload).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 9. Sign (ES256 - IEEE P1363)
    const signingInput = `${headerB64}.${payloadB64}`;
    
    // Use crypto.sign convenience method with dsaEncoding option (Node 15+)
    // This is critical for ES256 compliance with JWT standard
    const signature = crypto.sign("sha256", Buffer.from(signingInput), {
        key: privateKey,
        dsaEncoding: "ieee-p1363", 
    });

    const signatureB64 = signature.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 10. Return JWS Detached Format: header..signature
    console.log(`[AgidSigner] JWS Detached generated via Forge (Binary Fix).`);
    return `${headerB64}..${signatureB64}`;
}
