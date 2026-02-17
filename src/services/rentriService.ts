import https from 'https';
import crypto from 'crypto';
import fs from 'fs';
import { RENTRI_CONFIG, CompanyKey } from '../config';
import { buildRentriXml } from '../utils/xmlGenerator';
import { signAgidPayload, generateAuthJwt } from '../utils/agid_v2';
import { getRentriClient } from '../utils/clientFactory'; // Keep for other methods for now

// Helper to get P12 buffer directly
function getP12Buffer(company: CompanyKey): Buffer {
    const config = RENTRI_CONFIG[company];
    const base64EnvName = `RENTRI_CERT_BASE64_${company.toUpperCase()}`;
    const envBase64 = process.env[base64EnvName];

    if (envBase64 && envBase64.length > 100) {
        return Buffer.from(envBase64.replace(/[\r\n\s]/g, ''), 'base64');
    } else {
        return fs.readFileSync(config.certPath);
    }
}

export class RentriService {

    /**
     * NATIVE HTTPS IMPLEMENTATION of Vidimation to bypass Axios interference.
     */
    static async vidimateFir(company: string, quantity: number = 1): Promise<string[]> {
        console.log(`[RentriService] Starting REAL Vidimation (NATIVE HTTPS) for ${company} (Qty: ${quantity})...`);
        
        const config = RENTRI_CONFIG[company as CompanyKey];
        if (!config) throw new Error(`Config not found for company: ${company}`);

        let blockCode = 'FMGWB'; 
        if (company === 'multy') blockCode = 'FMGWB'; 

        // Construct URL CORRECTED
        const isTest = config.apiBase.includes('test') || config.apiBase.includes('demo');
        const hostname = isTest ? 'rentri.gov.it' : 'api.rentri.gov.it';
        
        // Correct path for vidimation: /vidimazione-formulari/v1.0/{blockCode}
        const path = `/vidimazione-formulari/v1.0/${blockCode}`;

        console.log(`[RentriService] Native Request to: https://${hostname}${path}`);

        // Prepare Body
        const body = JSON.stringify({ quantita: quantity });

        // Prepare Headers
        const authToken = generateAuthJwt(company as CompanyKey);
        const integritySignature = signAgidPayload(body, company as CompanyKey);
        const digest = crypto.createHash('sha256').update(body, 'utf8').digest('base64');
        const digestHeader = `SHA-256=${digest}`;

        const headers: Record<string, string> = {
            'Host': hostname,
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body).toString(),
            'Authorization': `Bearer ${authToken}`,
            'Agid-JWT-Signature': integritySignature,
            'Digest': digestHeader,
            'User-Agent': 'DragonRifiuti/1.0'
        };

        // API Key
        if (config.apiKey) headers['X-API-KEY'] = config.apiKey;
        else if (process.env.RENTRI_API_KEY_GLOBAL) headers['X-API-KEY'] = process.env.RENTRI_API_KEY_GLOBAL;

        // DEBUG HEADERS
        console.log(`[RentriService] Native Headers:`);
        console.log(JSON.stringify(headers, null, 2));

        // Get Certs
        const p12Buffer = getP12Buffer(company as CompanyKey);
        const passEnvName = `RENTRI_CERT_PASS_${company.toUpperCase()}`;
        const passphrase = process.env[passEnvName];

        return new Promise((resolve, reject) => {
            const options: https.RequestOptions = {
                hostname: hostname,
                port: 443,
                path: path,
                method: 'POST',
                headers: headers,
                pfx: p12Buffer,
                passphrase: passphrase,
                rejectUnauthorized: !isTest // Strict SSL in prod
            };

            const req = https.request(options, (res) => {
                console.log(`[RentriService] Response Status: ${res.statusCode}`);
                console.log(`[RentriService] Response Headers:`, res.headers);

                let data = '';
                res.on('data', (chunk) => { data += chunk; });
                res.on('end', () => {
                    console.log(`[RentriService] Response Body: ${data}`);
                    
                    if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                        try {
                            const json = JSON.parse(data);
                            if (Array.isArray(json)) resolve(json);
                            else if (json.numero_fir) resolve([json.numero_fir]);
                            else resolve([]); // Should not happen on success
                        } catch (e) {
                            reject(new Error(`Invalid JSON response: ${data}`));
                        }
                    } else {
                        reject(new Error(`Rentri Error ${res.statusCode}: ${data}`));
                    }
                });
            });

            req.on('error', (e) => {
                console.error(`[RentriService] Request Error: ${e.message}`);
                reject(e);
            });

            req.write(body);
            req.end();
        });
    }

    // Keep other methods using Axios for now, or migrate them if this works.
    // For consistency, I'll migrate createFir to Native as well since it uses same Auth.
    
    static async createFir(company: string, payload: any): Promise<any> {
        console.log(`[RentriService] Starting REAL Create FIR (NATIVE HTTPS) for ${company}...`);
        
        const config = RENTRI_CONFIG[company as CompanyKey];
        if (!config) throw new Error(`Config not found for company: ${company}`);

        // Construct URL for Emission
        // Prod: https://api.rentri.gov.it/formulari/v1.0
        const isTest = config.apiBase.includes('test') || config.apiBase.includes('demo');
        const hostname = isTest ? 'rentri.gov.it' : 'api.rentri.gov.it';
        // Base path is usually /formulari/v1.0. But axios config had full URL.
        // Assuming config.apiBase is "https://api.rentri.gov.it/formulari/v1.0"
        const urlObj = new URL(config.apiBase);
        const path = urlObj.pathname; // Should be /formulari/v1.0

        console.log(`[RentriService] Native Request to: https://${hostname}${path}`);

        const xmlContent = buildRentriXml(payload);
        const body = xmlContent;

        const authToken = generateAuthJwt(company as CompanyKey);
        const integritySignature = signAgidPayload(body, company as CompanyKey);
        const digest = crypto.createHash('sha256').update(body, 'utf8').digest('base64');
        const digestHeader = `SHA-256=${digest}`;

        const headers: Record<string, string> = {
            'Host': hostname,
            'Accept': 'application/xml',
            'Content-Type': 'application/xml',
            'Content-Length': Buffer.byteLength(body).toString(),
            'Authorization': `Bearer ${authToken}`,
            'Agid-JWT-Signature': integritySignature,
            'Digest': digestHeader,
            'User-Agent': 'DragonRifiuti/1.0'
        };

        if (config.apiKey) headers['X-API-KEY'] = config.apiKey;
        else if (process.env.RENTRI_API_KEY_GLOBAL) headers['X-API-KEY'] = process.env.RENTRI_API_KEY_GLOBAL;

        const p12Buffer = getP12Buffer(company as CompanyKey);
        const passEnvName = `RENTRI_CERT_PASS_${company.toUpperCase()}`;
        const passphrase = process.env[passEnvName];

        return new Promise((resolve, reject) => {
            const options: https.RequestOptions = {
                hostname: hostname,
                port: 443,
                path: path, // Post to root of /formulari/v1.0
                method: 'POST',
                headers: headers,
                pfx: p12Buffer,
                passphrase: passphrase,
                rejectUnauthorized: !isTest
            };

            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => { data += chunk; });
                res.on('end', () => {
                    console.log(`[RentriService] Create Response: ${res.statusCode} ${data}`);
                    if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                        // XML response usually? Or JSON? 
                        // Assuming caller handles response format, but usually it returns JSON or XML.
                        // For now return raw data or parsed if possible.
                        // Rentri create usually returns JSON with result.
                        try {
                            resolve(JSON.parse(data));
                        } catch {
                            resolve(data); // Return string if not JSON
                        }
                    } else {
                        reject(new Error(`Rentri Create Error ${res.statusCode}: ${data}`));
                    }
                });
            });

            req.on('error', (e) => reject(e));
            req.write(body);
            req.end();
        });
    }

    // Keep GET methods simple (Axios) or migrate later. 
    // Vidimate and Create are the critical ones blocking production.
    static async getPdf(company: string, numeroFir: string): Promise<Buffer> {
        const client = getRentriClient(company as CompanyKey);
        const endpoint = `/${numeroFir}/pdf`;
        try {
             // Re-add auth headers for Axios call
            const authToken = generateAuthJwt(company as CompanyKey);
            const integritySignature = signAgidPayload('', company as CompanyKey);
            const digest = crypto.createHash('sha256').update('', 'utf8').digest('base64');
            const digestHeader = `SHA-256=${digest}`;
            
            const response = await client.get(endpoint, {
                responseType: 'arraybuffer',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'Agid-JWT-Signature': integritySignature,
                    'Digest': digestHeader,
                    'Accept': 'application/pdf'
                }
            });
            return response.data;
        } catch (error: any) {
            throw new Error(`RENTRI API Error: ${error.message}`);
        }
    }

    static async getXfir(company: string, numeroFir: string): Promise<string> {
        const client = getRentriClient(company as CompanyKey);
        const endpoint = `/${numeroFir}/xfir`;
        try {
            const authToken = generateAuthJwt(company as CompanyKey);
            const integritySignature = signAgidPayload('', company as CompanyKey);
            const digest = crypto.createHash('sha256').update('', 'utf8').digest('base64');
            const digestHeader = `SHA-256=${digest}`;

            const response = await client.get(endpoint, {
                responseType: 'text',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'Agid-JWT-Signature': integritySignature,
                    'Digest': digestHeader,
                    'Accept': 'application/xml'
                }
            });
            return response.data;
        } catch (error: any) {
            throw new Error(`RENTRI API Error: ${error.message}`);
        }
    }
}
