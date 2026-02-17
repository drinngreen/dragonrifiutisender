import crypto from 'crypto';
import fs from 'fs';
import { spawnSync } from 'child_process';
import { RENTRI_CONFIG, CompanyKey, RENTRI_AUDIENCE } from '../config';

// Structure for keys
interface CertData {
    privateKey: string;
    certificate: string; // PEM
}

// CACHE to avoid extracting P12 every time (it's slow)
const certCache: Record<string, CertData> = {};

function getCertData(company: CompanyKey): CertData {
    if (certCache[company]) return certCache[company];

    const config = RENTRI_CONFIG[company];
    const passEnvName = `RENTRI_CERT_PASS_${company.toUpperCase()}`;
    const certPass = process.env[passEnvName];
    if (!certPass) throw new Error(`Password missing for ${company}`);

    let p12Buffer: Buffer;
    const base64EnvName = `RENTRI_CERT_BASE64_${company.toUpperCase()}`;
    const envBase64 = process.env[base64EnvName];

    if (envBase64 && envBase64.length > 100) {
        p12Buffer = Buffer.from(envBase64.replace(/[\r\n\s]/g, ''), 'base64');
    } else {
        if (!fs.existsSync(config.certPath)) throw new Error(`Certificate not found: ${config.certPath}`);
        p12Buffer = fs.readFileSync(config.certPath);
    }

    // Extract both Key and Cert
    const uniqueId = Date.now() + '_' + Math.random().toString(36).substr(2, 5);
    const p12Path = `/tmp/${uniqueId}.p12`;
    const passPath = `/tmp/${uniqueId}.txt`;
    const keyPath = `/tmp/${uniqueId}.key`;
    const crtPath = `/tmp/${uniqueId}.crt`;

    try {
        fs.writeFileSync(p12Path, p12Buffer);
        fs.writeFileSync(passPath, certPass);

        // 1. Extract Key
        let resKey = spawnSync('openssl', ['pkcs12', '-in', p12Path, '-nocerts', '-out', keyPath, '-nodes', '-passin', `file:${passPath}`, '-legacy']);
        if (resKey.status !== 0) {
             resKey = spawnSync('openssl', ['pkcs12', '-in', p12Path, '-nocerts', '-out', keyPath, '-nodes', '-passin', `file:${passPath}`]); // Try without legacy
        }
        
        // 2. Extract Cert (Leaf)
        let resCert = spawnSync('openssl', ['pkcs12', '-in', p12Path, '-clcerts', '-nokeys', '-out', crtPath, '-passin', `file:${passPath}`, '-legacy']);
        if (resCert.status !== 0) {
             resCert = spawnSync('openssl', ['pkcs12', '-in', p12Path, '-clcerts', '-nokeys', '-out', crtPath, '-passin', `file:${passPath}`]);
        }

        if (!fs.existsSync(keyPath) || !fs.existsSync(crtPath)) {
            throw new Error(`OpenSSL extraction failed. Key status: ${resKey.status}, Cert status: ${resCert.status}`);
        }

        const data = {
            privateKey: fs.readFileSync(keyPath, 'utf8'),
            certificate: fs.readFileSync(crtPath, 'utf8')
        };
        
        certCache[company] = data;
        return data;

    } finally {
        try {
            if (fs.existsSync(p12Path)) fs.unlinkSync(p12Path);
            if (fs.existsSync(passPath)) fs.unlinkSync(passPath);
            if (fs.existsSync(keyPath)) fs.unlinkSync(keyPath);
            if (fs.existsSync(crtPath)) fs.unlinkSync(crtPath);
        } catch {}
    }
}

// Helper to get x5c (Base64 of DER) from PEM
function getX5c(pem: string): string[] {
    // Remove headers/footers and newlines
    const base64 = pem
        .replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/[\r\n\s]/g, '');
    return [base64];
}

/**
 * Generates the AgID-JWT-Signature (Integrity Token)
 * Matches C# structure:
 * - Header: { alg: ES256, typ: JWT, x5c: [...] }
 * - Payload: { digest: SHA256(body), signed_headers: [{ digest, content-type }], ... }
 */
export function signAgidPayload(body: string, company: CompanyKey): string {
    const { privateKey, certificate } = getCertData(company);
    const config = RENTRI_CONFIG[company];
    const now = Math.floor(Date.now() / 1000);

    // 1. Calculate Digest of Body
    const digest = crypto.createHash('sha256').update(body, 'utf8').digest('base64');
    const digestHeader = `SHA-256=${digest}`;

    // 2. Prepare Payload
    const payload = {
        iss: config.issuer,
        sub: config.issuer,
        aud: RENTRI_AUDIENCE,
        iat: now,
        exp: now + 300, // 5 mins
        jti: crypto.randomUUID(),
        // IMPORTANT: AgID Integrity claims
        digest: digestHeader,
        signed_headers: [
            { digest: digestHeader },
            { "content-type": "application/json" }
        ]
    };

    // 3. Prepare Header with x5c
    const header = {
        alg: 'ES256',
        typ: 'JWT',
        x5c: getX5c(certificate)
    };

    // 4. Sign
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    
    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = crypto.sign("sha256", Buffer.from(signingInput), {
        key: privateKey,
        dsaEncoding: "ieee-p1363"
    }).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // FULL JWT: header.payload.signature
    // This matches the C# implementation which uses JsonWebTokenHandler.CreateToken (produces full JWT)
    return `${headerB64}.${payloadB64}.${signature}`;
}

/**
 * Generates the Authorization Bearer Token
 * Header: { alg: ES256, typ: JWT, kid: SHA256(Cert) } -> Reduced size
 * Payload: { iss, sub, aud, iat, exp, jti }
 */
export function generateAuthJwt(company: CompanyKey): string {
    const { privateKey, certificate } = getCertData(company);
    const config = RENTRI_CONFIG[company];
    const now = Math.floor(Date.now() / 1000);

    const payload = {
        iss: config.issuer,
        sub: config.issuer,
        aud: RENTRI_AUDIENCE,
        iat: now,
        exp: now + 300,
        jti: crypto.randomUUID()
    };

    // CALCULATE KID (SHA-256 Fingerprint of Cert) instead of sending full x5c
    const certDer = Buffer.from(getX5c(certificate)[0], 'base64');
    const thumbprint = crypto.createHash('sha256').update(certDer).digest('hex');

    const header = {
        alg: 'ES256',
        typ: 'JWT',
        kid: thumbprint // USE KID INSTEAD OF X5C TO REDUCE SIZE
    };

    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    
    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = crypto.sign("sha256", Buffer.from(signingInput), {
        key: privateKey,
        dsaEncoding: "ieee-p1363"
    }).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    const token = `${headerB64}.${payloadB64}.${signature}`;
    console.log(`[AuthJwt] Token Length: ${token.length} chars (Should be < 4000)`);
    return token;
}
