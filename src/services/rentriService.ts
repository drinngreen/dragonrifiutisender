import { getRentriClient } from '../utils/clientFactory';
import { RENTRI_CONFIG, CompanyKey } from '../config';
import { buildRentriXml } from '../utils/xmlGenerator';
import { signAgidPayload } from '../utils/agid_v2';

export class RentriService {

    /**
     * Vidimates one or more FIR numbers from RENTRI.
     * @param company Company key (global, multy, etc.)
     * @param quantity Number of FIRs to generate (default: 1)
     * @returns Array of FIR numbers (e.g. ["FMGWB00001", "FMGWB00002"])
     */
    static async vidimateFir(company: string, quantity: number = 1): Promise<string[]> {
        console.log(`[RentriService] Starting REAL Vidimation for ${company} (Qty: ${quantity})...`);
        
        const client = getRentriClient(company as CompanyKey);
        
        // VIDIMATION CONFIGURATION
        let blockCode = 'FMGWB'; // Default for Global
        if (company === 'multy') blockCode = 'FMGWB'; // Change if Multy has a different block
        
        // Endpoint: /vidimazione-formulari/v1.0/{blockCode}
        const baseURL = client.defaults.baseURL || '';
        let vidimationUrl = '';
        if (baseURL.includes('/formulari/v1.0')) {
             vidimationUrl = baseURL.replace('/formulari/v1.0', `/vidimazione-formulari/v1.0/${blockCode}`);
        } else {
             vidimationUrl = `/vidimazione-formulari/v1.0/${blockCode}`;
        }

        console.log(`[RentriService] Calling Vidimation Endpoint: ${vidimationUrl}`);

        try {
            // Request Body: Quantity
            const body = { 
                quantita: quantity 
            };
            
            const response = await client.post(vidimationUrl, body, {
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            });

            console.log(`[RentriService] Vidimation Response:`, JSON.stringify(response.data));

            // Expecting array of numbers. Example: ["FMGWB00001", ...]
            if (Array.isArray(response.data)) {
                console.log(`[RentriService] Received ${response.data.length} FIR numbers.`);
                return response.data;
            } else if (response.data && response.data.numero_fir) {
                // Fallback for single object response
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
        
        let agidSignature = '';
        try {
            agidSignature = signAgidPayload(xmlContent, company as CompanyKey);
        } catch (e: any) {
            console.error(`[RentriService] Failed to generate Agid Signature: ${e.message}`);
            throw new Error(`Signature Error: ${e.message}`);
        }

        const client = getRentriClient(company as CompanyKey);
        const endpoint = '/'; 
        
        console.log(`[RentriService] SENDING REAL XML to ${client.defaults.baseURL}${endpoint}`);
        
        const headers = {
            'Agid-JWT-Signature': agidSignature,
            'Content-Type': 'application/xml',
            'Accept': 'application/xml'
        };
        
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
        const endpoint = `/${numeroFir}/pdf`;
        
        console.log(`[RentriService] Downloading PDF for ${numeroFir}...`);
        
        try {
            const response = await client.get(endpoint, {
                responseType: 'arraybuffer',
                headers: { 'Accept': 'application/pdf' }
            });
            return response.data;
        } catch (error: any) {
            console.error(`[RentriService] PDF Download Failed:`, error.message);
            throw new Error(`RENTRI API Error: ${error.message}`);
        }
    }

    static async getXfir(company: string, numeroFir: string): Promise<string> {
        const client = getRentriClient(company as CompanyKey);
        const endpoint = `/${numeroFir}/xfir`;
        
        console.log(`[RentriService] Downloading xFIR for ${numeroFir}...`);
        
        try {
            const response = await client.get(endpoint, {
                responseType: 'text',
                headers: { 'Accept': 'application/xml' }
            });
            return response.data;
        } catch (error: any) {
            console.error(`[RentriService] xFIR Download Failed:`, error.message);
            throw new Error(`RENTRI API Error: ${error.message}`);
        }
    }
}
