import crypto from 'crypto';
import fs from 'fs';
import { spawnSync } from 'child_process';
import { RENTRI_CONFIG, CompanyKey } from '../config';

/**
 * Generates an Agid-JWT-Signature in JWS Detached format using ES256 algorithm.
 * Includes DEBUGGING for P12 integrity and OpenSSL verification.
 */
export function signAgidPayload(payload: string, company: CompanyKey): string {
    const config = RENTRI_CONFIG[company];
    if (!config) throw new Error(`Config not found for company: ${company}`);

    const certPath = config.certPath; 
    const certPass = company === 'global' 
        ? process.env.RENTRI_CERT_PASS_GLOBAL 
        : process.env.RENTRI_CERT_PASS_MULTY;

    if (!certPass) throw new Error(`Password missing for ${company}`);

    // 1. Get P12 Content
    let p12Buffer: Buffer;
    
    const envBase64 = company === 'global' 
        ? process.env.RENTRI_CERT_BASE64_GLOBAL 
        : process.env.RENTRI_CERT_BASE64_MULTY;

    if (envBase64 && envBase64.length > 100) {
        console.log(`[AgidSigner] Using Base64 Certificate from Env Var for ${company}`);
        const cleanBase64 = envBase64.replace(/[\r\n\s]/g, '');
        p12Buffer = Buffer.from(cleanBase64, 'base64');
        
        // DEBUG: Integrity Check
        const sha256 = crypto.createHash('sha256').update(p12Buffer).digest('hex');
        console.log(`[AgidSigner] P12 Buffer SHA256: ${sha256}`);
        console.log(`[AgidSigner] P12 Buffer Size: ${p12Buffer.length} bytes`);
        
    } else {
        console.log(`[AgidSigner] Reading P12 from file: ${certPath}`);
        if (!fs.existsSync(certPath)) throw new Error(`Certificate not found at: ${certPath}`);
        p12Buffer = fs.readFileSync(certPath);
    }

    // 2. Prepare temporary paths
    const uniqueId = Date.now().toString() + Math.random().toString().slice(2,6);
    const tempP12Path = `/tmp/cert_${uniqueId}.p12`;
    const tempPassPath = `/tmp/pass_${uniqueId}.txt`;
    const tempKeyPath = `/tmp/key_${uniqueId}.pem`;

    let privateKeyPem: string;

    try {
        fs.writeFileSync(tempP12Path, p12Buffer);
        fs.writeFileSync(tempPassPath, certPass);

        // DEBUG: Verify P12 structure
        console.log(`[AgidSigner] Verifying P12 structure with OpenSSL...`);
        const infoResult = spawnSync('openssl', ['pkcs12', '-info', '-in', tempP12Path, '-nokeys', '-nocerts', '-passin', `file:${tempPassPath}`, '-legacy']);
        
        if (infoResult.status !== 0) {
             console.error(`[AgidSigner] P12 Verify FAILED. Stderr: ${infoResult.stderr.toString()}`);
             // Proceed anyway, maybe extraction works even if info fails (unlikely)
        } else {
             console.log(`[AgidSigner] P12 Verify OK.`);
        }

        // Run OpenSSL to extract key
        let result = spawnSync('openssl', [
            'pkcs12',
            '-in', tempP12Path,
            '-nocerts',
            '-out', tempKeyPath,
            '-nodes',
            '-passin', `file:${tempPassPath}`,
            '-legacy'
        ]);

        if (result.status !== 0) {
            console.log(`[AgidSigner] OpenSSL (Legacy) failed, retrying without -legacy flag...`);
            result = spawnSync('openssl', [
                'pkcs12',
                '-in', tempP12Path,
                '-nocerts',
                '-out', tempKeyPath,
                '-nodes',
                '-passin', `file:${tempPassPath}`
            ]);
        }

        if (result.status !== 0) {
            const stderr = result.stderr.toString();
            console.error(`[AgidSigner] OpenSSL Extraction Stderr: ${stderr}`);
            throw new Error(`OpenSSL failed with code ${result.status}: ${stderr}`);
        }

        privateKeyPem = fs.readFileSync(tempKeyPath, 'utf8');

    } catch (e: any) {
        throw new Error(`Failed to extract private key via OpenSSL: ${e.message}`);
    } finally {
        try {
            if (fs.existsSync(tempP12Path)) fs.unlinkSync(tempP12Path);
            if (fs.existsSync(tempPassPath)) fs.unlinkSync(tempPassPath);
            if (fs.existsSync(tempKeyPath)) fs.unlinkSync(tempKeyPath);
        } catch (cleanupErr) {
            console.warn(`[AgidSigner] Cleanup warning: ${cleanupErr}`);
        }
    }

    // 3. Import into Node Crypto
    const privateKeyObj = crypto.createPrivateKey(privateKeyPem);

    // 4. JWS Header (ES256)
    const header = { alg: 'ES256', typ: 'JWT' };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const payloadB64 = Buffer.from(payload).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 5. Sign
    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = crypto.sign("sha256", Buffer.from(signingInput), {
        key: privateKeyObj,
        dsaEncoding: "ieee-p1363", 
    });

    const signatureB64 = signature.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 6. Return JWS Detached Format
    const finalSignature = `${headerB64}..${signatureB64}`;
    console.log(`[AgidSigner] Generated JWS Length: ${finalSignature.length} chars`);
    return finalSignature;
}
