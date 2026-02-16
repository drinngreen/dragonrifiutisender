import crypto from 'crypto';
import fs from 'fs';
import forge from 'node-forge';
import { RENTRI_CONFIG, CompanyKey } from '../config';

/**
 * Generates an Agid-JWT-Signature in JWS Detached format.
 * Uses node-forge to safely extract private key from P12/PFX,
 * bypassing Node.js native crypto PFX limitations.
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

    // 1. Extract Private Key using node-forge (Robust Method)
    let privateKeyPem: string;
    try {
        console.log(`[AgidSigner] Loading P12 via Forge from ${certPath}`);
        
        // Read file as binary string for forge
        const p12Der = fs.readFileSync(certPath, 'binary');
        const p12Asn1 = forge.asn1.fromDer(p12Der);
        
        // Decrypt P12
        const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, certPass);
        
        // Get Key Bags
        const bags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
        let keyBag = bags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0];

        // Fallback to non-shrouded key bag if needed
        if (!keyBag) {
            const bagsUnshrouded = p12.getBags({ bagType: forge.pki.oids.keyBag });
            keyBag = bagsUnshrouded[forge.pki.oids.keyBag]?.[0];
        }

        if (!keyBag) {
            throw new Error("No private key found in P12 file bags");
        }

        // Convert Forge Key to PEM
        privateKeyPem = forge.pki.privateKeyToPem(keyBag.key);
        // console.log("Private Key extracted successfully (PEM length: " + privateKeyPem.length + ")");

    } catch (e: any) {
        console.error(`[AgidSigner] Forge Error:`, e);
        throw new Error(`Failed to extract private key via Forge: ${e.message}`);
    }

    // 2. Import into Node Crypto (Standard PEM is safe)
    const privateKey = crypto.createPrivateKey(privateKeyPem);

    // 3. Create JWS Header (Minimal)
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

    // 6. Return JWS Detached Format: header..signature
    console.log(`[AgidSigner] Signature generated successfully via Forge.`);
    return `${headerB64}..${signatureB64}`;
}
