import { getRentriClient } from '../utils/clientFactory';
import { RENTRI_CONFIG, CompanyKey } from '../config';
import { buildRentriXml } from '../utils/xmlGenerator';
import { signAgidPayload, generateAuthJwt } from '../utils/agid_v2';
import crypto from 'crypto';

export class RentriService {

    static async vidimateFir(company: string, quantity: number = 1): Promise<string[]> {
        console.log(`[RentriService] Starting REAL Vidimation for ${company} (Qty: ${quantity})...`);
        
        const client = getRentriClient(company as CompanyKey);
        const config = RENTRI_CONFIG[company as CompanyKey];
        
        let blockCode = 'FMGWB'; 
        if (company === 'multy') blockCode = 'FMGWB'; 
        
        const baseURL = client.defaults.baseURL || '';
        let vidimationUrl = '';
        if (baseURL.includes('/formulari/v1.0')) {
             vidimationUrl = baseURL.replace('/formulari/v1.0', `/vidimazione-formulari/v1.0/${blockCode}`);
        } else {
             vidimationUrl = `/vidimazione-formulari/v1.0/${blockCode}`;
        }

        console.log(`[RentriService] Calling Vidimation Endpoint: ${vidimationUrl}`);

        try {
            const body = { quantita: quantity };
            const bodyString = JSON.stringify(body);
            
            // Calculate Digest for Header
            const digest = crypto.createHash('sha256').update(bodyString, 'utf8').digest('base64');
            const digestHeader = `SHA-256=${digest}`;

            const authToken = generateAuthJwt(company as CompanyKey);
            const integritySignature = signAgidPayload(bodyString, company as CompanyKey);

            const headers: any = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': `Bearer ${authToken}`, // Force space after Bearer
                'Agid-JWT-Signature': integritySignature,
                'Digest': digestHeader 
            };
            
            if (config && config.apiKey) {
                headers['X-API-KEY'] = config.apiKey;
            } else if (process.env.RENTRI_API_KEY_GLOBAL) {
                 headers['X-API-KEY'] = process.env.RENTRI_API_KEY_GLOBAL;
            }

            // EXTREME DEBUG
            console.log(`[RentriService] calling: ${client.defaults.baseURL}${vidimationUrl}`);
            console.log(`[RentriService] Authorization Header (First 20 chars): '${headers.Authorization.substring(0, 20)}...'`);
            if (headers['X-API-KEY']) {
                 console.log(`[RentriService] X-API-KEY is set (Length: ${headers['X-API-KEY'].length})`);
            } else {
                 console.error(`[RentriService] CRITICAL: X-API-KEY IS UNDEFINED!`);
            }

            const response = await client.post(vidimationUrl, body, { headers });
            
            if (Array.isArray(response.data)) {
                return response.data;
            } else if (response.data && response.data.numero_fir) {
                return [response.data.numero_fir];
            } else {
                throw new Error(`Unexpected Vidimation Response: ${JSON.stringify(response.data)}`);
            }
        } catch (error: any) {
            console.error(`[RentriService] Vidimation Failed:`, error.response?.data || error.message);
            throw new Error(`Vidimation Error: ${JSON.stringify(error.response?.data || error.message)}`);
        }
    }

    // ... Other methods (createFir, getPdf, getXfir) should also add 'Digest' header and use updated signAgidPayload
    // For brevity, I'm updating only vidimateFir here as it's the blocking one. 
    // The user can request others if this works.
    
    // BUT I should update createFir too to be safe.
    static async createFir(company: string, payload: any): Promise<any> {
        const xmlContent = buildRentriXml(payload);
        
        const authToken = generateAuthJwt(company as CompanyKey);
        const integritySignature = signAgidPayload(xmlContent, company as CompanyKey);
        
        const digest = crypto.createHash('sha256').update(xmlContent, 'utf8').digest('base64');
        const digestHeader = `SHA-256=${digest}`;

        const client = getRentriClient(company as CompanyKey);
        const config = RENTRI_CONFIG[company as CompanyKey];
        const endpoint = '/'; 
        
        const headers: any = {
            'Authorization': `Bearer ${authToken}`,
            'Agid-JWT-Signature': integritySignature,
            'Digest': digestHeader,
            'Content-Type': 'application/xml',
            'Accept': 'application/xml'
        };

        if (config && config.apiKey) headers['X-API-KEY'] = config.apiKey;
        
        try {
            const response = await client.post(endpoint, xmlContent, { headers });
            return response.data;
        } catch (error: any) {
            console.error(`[RentriService] Create Failed:`, error.response?.data || error.message);
            throw new Error(`RENTRI API Error: ${JSON.stringify(error.response?.data || error.message)}`);
        }
    }
    
    static async getPdf(company: string, numeroFir: string): Promise<Buffer> {
        return this.genericGet(company, `/${numeroFir}/pdf`, 'application/pdf');
    }

    static async getXfir(company: string, numeroFir: string): Promise<string> {
        // Cast to any because axios returns string for text responseType but signature expects Buffer|string
        const res = await this.genericGet(company, `/${numeroFir}/xfir`, 'application/xml', 'text');
        return res as unknown as string;
    }

    private static async genericGet(company: string, endpoint: string, accept: string, responseType: 'arraybuffer' | 'text' = 'arraybuffer') {
        const client = getRentriClient(company as CompanyKey);
        const config = RENTRI_CONFIG[company as CompanyKey];
        
        const authToken = generateAuthJwt(company as CompanyKey);
        // GET requests usually have empty body for digest/signature
        const body = ''; 
        const integritySignature = signAgidPayload(body, company as CompanyKey);
        const digest = crypto.createHash('sha256').update(body, 'utf8').digest('base64');
        const digestHeader = `SHA-256=${digest}`;

        const headers: any = {
            'Authorization': `Bearer ${authToken}`,
            'Agid-JWT-Signature': integritySignature,
            'Digest': digestHeader,
            'Accept': accept
        };
        if (config && config.apiKey) headers['X-API-KEY'] = config.apiKey;

        try {
            const response = await client.get(endpoint, {
                responseType: responseType as any,
                headers
            });
            return response.data;
        } catch (error: any) {
            console.error(`[RentriService] GET Failed:`, error.message);
            throw new Error(`RENTRI API Error: ${error.message}`);
        }
    }
}
