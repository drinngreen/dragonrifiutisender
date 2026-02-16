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
    if (!config) {
        throw new Error(`Config not found for company: ${company}`);
    }

    const certPath = config.certPath;
    
    // Read password from environment variables
    const certPass = company === 'global' 
        ? process.env.RENTRI_CERT_PASS_GLOBAL 
        : process.env.RENTRI_CERT_PASS_MULTY;

    if (!certPass) {
        console.warn(`[Warning] No certificate password found for ${company}. Ensure RENTRI_CERT_PASS_${company.toUpperCase()} is set.`);
    }

    if (!fs.existsSync(certPath)) {
        throw new Error(`Certificate file not found at: ${certPath}`);
    }

    console.log(`[ClientFactory] Loading cert for ${company} from ${certPath}`);

    // Create HTTPS Agent with mTLS
    const httpsAgent = new https.Agent({
        pfx: fs.readFileSync(certPath),
        passphrase: certPass || undefined,
        // In PROD, verify CA. In SANDBOX/TEST, allow self-signed or untrusted if needed.
        // Usually RENTRI PROD has trusted CA, but sometimes intermediate certs are tricky.
        rejectUnauthorized: RENTRI_ENV === 'PRODUCTION' 
    });

    const client = axios.create({
        baseURL: config.apiBase,
        httpsAgent,
        headers: {
            'Content-Type': 'application/xml',
            'Accept': 'application/xml',
            // Add API Key if present (some services require both mTLS + Key)
            ...(config.apiKey ? { 'X-API-KEY': config.apiKey } : {}) 
        }
    });

    clients[company] = client;
    return client;
}
