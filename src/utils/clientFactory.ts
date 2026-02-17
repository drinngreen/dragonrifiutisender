import axios, { AxiosInstance } from 'axios';
import https from 'https';
import fs from 'fs';
import { RENTRI_CONFIG, CompanyKey, RENTRI_ENV } from '../config';

// Cache clients per company to avoid reloading certs on every request
const clients: Partial<Record<CompanyKey, AxiosInstance>> = {};

export function getRentriClient(company: CompanyKey): AxiosInstance {
    if (clients[company]) {
        return clients[company]!;
    }

    const config = RENTRI_CONFIG[company];
    if (!config) throw new Error(`Config not found for company: ${company}`);

    // DYNAMIC ENV VAR ACCESS
    const passEnvName = `RENTRI_CERT_PASS_${company.toUpperCase()}`;
    const certPass = process.env[passEnvName];

    if (!certPass) {
        console.warn(`[Warning] No certificate password found for ${company}. Ensure ${passEnvName} is set.`);
    }

    // LOGIC: Try Base64 Env Var first, then File
    let pfxBuffer: Buffer;
    
    const base64EnvName = `RENTRI_CERT_BASE64_${company.toUpperCase()}`;
    const envBase64 = process.env[base64EnvName];

    if (envBase64 && envBase64.length > 100) {
        console.log(`[ClientFactory] Using Base64 Certificate for mTLS (${company}) from ${base64EnvName}`);
        // Clean up base64 string
        const cleanBase64 = envBase64.replace(/[\r\n\s]/g, '');
        pfxBuffer = Buffer.from(cleanBase64, 'base64');
    } else {
        // Fallback to file system
        const certPath = config.certPath;
        if (!fs.existsSync(certPath)) {
            // Provide a clear error if neither Env Var nor File is found
            throw new Error(`Certificate not found! Checked Env Var '${base64EnvName}' and File '${certPath}'`);
        }
        console.log(`[ClientFactory] Loading cert from file: ${certPath}`);
        pfxBuffer = fs.readFileSync(certPath);
    }

    // Create HTTPS Agent with mTLS
    const httpsAgent = new https.Agent({
        pfx: pfxBuffer, // Pass Buffer directly
        passphrase: certPass || undefined,
        // In PROD, verify CA. In SANDBOX/TEST, allow self-signed or untrusted if needed.
        rejectUnauthorized: RENTRI_ENV === 'PRODUCTION' 
    });

    const client = axios.create({
        baseURL: config.apiBase,
        httpsAgent,
        headers: {
            'Content-Type': 'application/xml',
            'Accept': 'application/xml',
            ...(config.apiKey ? { 'X-API-KEY': config.apiKey } : {}) 
        }
    });

    clients[company] = client;
    return client;
}
