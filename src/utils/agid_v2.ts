import crypto from 'crypto';
import fs from 'fs';
import { spawnSync } from 'child_process';
import { RENTRI_CONFIG, CompanyKey, RENTRI_AUDIENCE } from '../config';

// HELPER: Get Private Key (Shared logic)
function getPrivateKey(company: CompanyKey): string {
    const config = RENTRI_CONFIG[company];
    if (!config) throw new Error(`Config not found for company: ${company}`);

    const passEnvName = `RENTRI_CERT_PASS_${company.toUpperCase()}`;
    const certPass = process.env[passEnvName];
    if (!certPass) throw new Error(`Password missing for ${company}`);

    let p12Buffer: Buffer;
    const base64EnvName = `RENTRI_CERT_BASE64_${company.toUpperCase()}`;
    const envBase64 = process.env[base64EnvName];

    if (envBase64 && envBase64.length > 100) {
        console.log(`[AgidSigner] Using Base64 Certificate from Env Var for ${company}`);
        const cleanBase64 = envBase64.replace(/[\r\n\s]/g, '');
        p12Buffer = Buffer.from(cleanBase64, 'base64');
    } else {
        const certPath = config.certPath; 
        console.log(`[AgidSigner] Reading P12 from file: ${certPath}`);
        if (!fs.existsSync(certPath)) throw new Error(`Certificate not found at: ${certPath}`);
        p12Buffer = fs.readFileSync(certPath);
    }

    // Extract Key using OpenSSL (Robust method)
    const uniqueId = Date.now().toString() + Math.random().toString().slice(2,6);
    const tempP12Path = `/tmp/cert_${uniqueId}.p12`;
    const tempPassPath = `/tmp/pass_${uniqueId}.txt`;
    const tempKeyPath = `/tmp/key_${uniqueId}.pem`;

    try {
        fs.writeFileSync(tempP12Path, p12Buffer);
        fs.writeFileSync(tempPassPath, certPass);

        let result = spawnSync('openssl', [
            'pkcs12', '-in', tempP12Path, '-nocerts', '-out', tempKeyPath,
            '-nodes', '-passin', `file:${tempPassPath}`, '-legacy'
        ]);

        if (result.status !== 0) {
            // Retry without legacy
            result = spawnSync('openssl', [
                'pkcs12', '-in', tempP12Path, '-nocerts', '-out', tempKeyPath,
                '-nodes', '-passin', `file:${tempPassPath}`
            ]);
        }

        if (result.status !== 0) {
            throw new Error(`OpenSSL failed: ${result.stderr.toString()}`);
        }

        return fs.readFileSync(tempKeyPath, 'utf8');

    } finally {
        try {
            if (fs.existsSync(tempP12Path)) fs.unlinkSync(tempP12Path);
            if (fs.existsSync(tempPassPath)) fs.unlinkSync(tempPassPath);
            if (fs.existsSync(tempKeyPath)) fs.unlinkSync(tempKeyPath);
        } catch (e) { /* ignore cleanup errors */ }
    }
}

/**
 * Generates an Agid-JWT-Signature in JWS Detached format (header..signature)
 * Used for Integrity of the Body.
 */
export function signAgidPayload(payload: string, company: CompanyKey): string {
    const privateKeyPem = getPrivateKey(company);
    const privateKeyObj = crypto.createPrivateKey(privateKeyPem);
    const config = RENTRI_CONFIG[company];

    // JWS Detached Header
    // IMPORTANT: "cty" might be required? Usually not for AgID integrity.
    const header = { alg: 'ES256', typ: 'JWT' };
    
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const payloadB64 = Buffer.from(payload).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = crypto.sign("sha256", Buffer.from(signingInput), {
        key: privateKeyObj,
        dsaEncoding: "ieee-p1363", // STANDARD TASSATIVO
    });

    const signatureB64 = signature.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // JWS Detached: header..signature
    const detached = `${headerB64}..${signatureB64}`;
    console.log(`[AgidSigner] JWS Detached generated for ${company}. Length: ${detached.length}`);
    return detached;
}

/**
 * Generates a Standard JWT for Authorization (header.payload.signature)
 * Used for Bearer Token.
 */
export function generateAuthJwt(company: CompanyKey): string {
    const privateKeyPem = getPrivateKey(company);
    const privateKeyObj = crypto.createPrivateKey(privateKeyPem);
    const config = RENTRI_CONFIG[company];
    
    // Validate Issuer
    if (!config.issuer) throw new Error(`Issuer (CF/P.IVA) not configured for ${company}`);

    // Standard Auth Claims
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        iss: config.issuer, // MUST BE CF/P.IVA from Certificate
        sub: config.issuer, // MUST BE CF/P.IVA from Certificate
        aud: RENTRI_AUDIENCE, // MUST BE 'rentrigov.api' (Prod) or 'rentrigov.demo.api'
        iat: now,
        exp: now + 600, // 10 minutes validity
        jti: crypto.randomUUID()
    };
    
    console.log(`[AuthJwt] Generating Token. Iss: ${payload.iss}, Aud: ${payload.aud}`);

    const header = { alg: 'ES256', typ: 'JWT' };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = crypto.sign("sha256", Buffer.from(signingInput), {
        key: privateKeyObj,
        dsaEncoding: "ieee-p1363", // STANDARD TASSATIVO
    });

    const signatureB64 = signature.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // Standard JWT: header.payload.signature
    return `${headerB64}.${payloadB64}.${signatureB64}`;
}
