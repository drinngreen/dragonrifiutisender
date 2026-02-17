import { getRentriClient } from '../utils/clientFactory';
import { RENTRI_CONFIG, CompanyKey } from '../config';
import { buildRentriXml } from '../utils/xmlGenerator';
import { signAgidPayload, generateAuthJwt } from '../utils/agid_v2';

export class RentriService {

    /**
     * Vidimates one or more FIR numbers from RENTRI.
     */
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
            const authToken = generateAuthJwt(company as CompanyKey);
            const integritySignature = signAgidPayload(bodyString, company as CompanyKey);

            const headers: any = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': `Bearer ${authToken}`,
                'Agid-JWT-Signature': integritySignature
            };
            
            if (config && config.apiKey) headers['X-API-KEY'] = config.apiKey;

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

    static async createFir(company: string, payload: any): Promise<any> {
        const xmlContent = buildRentriXml(payload);
        
        // --- FIX: Apply AgID Auth to createFir as well ---
        const authToken = generateAuthJwt(company as CompanyKey);
        // Signature for XML payload (integrity)
        let agidSignature = '';
        try {
            agidSignature = signAgidPayload(xmlContent, company as CompanyKey);
        } catch (e: any) {
            console.error(`[RentriService] Failed to generate Agid Signature: ${e.message}`);
            throw new Error(`Signature Error: ${e.message}`);
        }

        const client = getRentriClient(company as CompanyKey);
        const config = RENTRI_CONFIG[company as CompanyKey];
        const endpoint = '/'; 
        
        console.log(`[RentriService] SENDING REAL XML to ${client.defaults.baseURL}${endpoint}`);
        
        const headers: any = {
            'Authorization': `Bearer ${authToken}`,
            'Agid-JWT-Signature': agidSignature,
            'Content-Type': 'application/xml',
            'Accept': 'application/xml'
        };

        if (config && config.apiKey) headers['X-API-KEY'] = config.apiKey;
        
        try {
            const response = await client.post(endpoint, xmlContent, { headers });
            console.log(`[RentriService] SUCCESS: ${response.status}`, response.data);
            return response.data;

        } catch (error: any) {
            console.error(`[RentriService] FAILED:`, error.response?.data || error.message);
            if (error.response) {
                console.error(`Status: ${error.response.status}`);
                console.error(`Data: ${JSON.stringify(error.response.data)}`);
            }
            throw new Error(`RENTRI API Error: ${JSON.stringify(error.response?.data || error.message)}`);
        }
    }

    static async getPdf(company: string, numeroFir: string): Promise<Buffer> {
        const client = getRentriClient(company as CompanyKey);
        const config = RENTRI_CONFIG[company as CompanyKey];
        const endpoint = `/${numeroFir}/pdf`;
        
        console.log(`[RentriService] Downloading PDF for ${numeroFir}...`);
        
        // --- FIX: Apply AgID Auth to PDF Download ---
        const authToken = generateAuthJwt(company as CompanyKey);
        // For GET requests, the integrity signature is usually computed on empty body or specific headers.
        // But RENTRI might just require the Authorization header for GETs.
        // Let's add at least Authorization. If Signature is needed for GET, it's usually on empty string.
        const integritySignature = signAgidPayload('', company as CompanyKey); 

        const headers: any = {
            'Authorization': `Bearer ${authToken}`,
            'Agid-JWT-Signature': integritySignature, // Signature of empty body
            'Accept': 'application/pdf'
        };
        if (config && config.apiKey) headers['X-API-KEY'] = config.apiKey;

        try {
            const response = await client.get(endpoint, {
                responseType: 'arraybuffer',
                headers
            });
            return response.data;
        } catch (error: any) {
            console.error(`[RentriService] PDF Download Failed:`, error.message);
            throw new Error(`RENTRI API Error: ${error.message}`);
        }
    }

    static async getXfir(company: string, numeroFir: string): Promise<string> {
        const client = getRentriClient(company as CompanyKey);
        const config = RENTRI_CONFIG[company as CompanyKey];
        const endpoint = `/${numeroFir}/xfir`;
        
        console.log(`[RentriService] Downloading xFIR for ${numeroFir}...`);
        
        // --- FIX: Apply AgID Auth to xFIR Download ---
        const authToken = generateAuthJwt(company as CompanyKey);
        const integritySignature = signAgidPayload('', company as CompanyKey); 

        const headers: any = {
            'Authorization': `Bearer ${authToken}`,
            'Agid-JWT-Signature': integritySignature,
            'Accept': 'application/xml'
        };
        if (config && config.apiKey) headers['X-API-KEY'] = config.apiKey;

        try {
            const response = await client.get(endpoint, {
                responseType: 'text',
                headers
            });
            return response.data;
        } catch (error: any) {
            console.error(`[RentriService] xFIR Download Failed:`, error.message);
            throw new Error(`RENTRI API Error: ${error.message}`);
        }
    }
}
