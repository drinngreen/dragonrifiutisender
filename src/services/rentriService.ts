import { getRentriClient } from '../utils/clientFactory';
import { RENTRI_CONFIG, CompanyKey } from '../config';
import { buildRentriXml } from '../utils/xmlGenerator';
import { signAgidPayload } from '../utils/agid';

export class RentriService {

    static async vidimateFir(company: string): Promise<string> {
        const mockNumber = `FIR-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        console.log(`[RentriService] Vidimated mock number: ${mockNumber} for ${company}`);
        return mockNumber;
    }

    static async createFir(company: string, payload: any): Promise<any> {
        // 1. Generate XML
        const xmlContent = buildRentriXml(payload);
        
        // 2. Generate Agid-JWT-Signature (JWS Detached)
        let agidSignature = '';
        try {
            agidSignature = signAgidPayload(xmlContent, company as CompanyKey);
        } catch (e: any) {
            console.error(`[RentriService] Failed to generate Agid Signature: ${e.message}`);
            // If signature fails, we probably can't proceed, but let's try anyway or throw
            throw new Error(`Signature Error: ${e.message}`);
        }

        // 3. Get Real mTLS Client
        const client = getRentriClient(company as CompanyKey);

        // 4. Send to RENTRI - REAL CALL
        // Endpoint: /fir/emissione (DA CONFERMARE SULLA DOC RENTRI)
        const endpoint = '/fir/emissione'; 
        
        console.log(`[RentriService] SENDING REAL XML to ${client.defaults.baseURL}${endpoint}`);
        
        try {
            const response = await client.post(endpoint, xmlContent, {
                headers: {
                    'Agid-JWT-Signature': agidSignature,
                    'Content-Type': 'application/xml',
                    'Accept': 'application/xml'
                }
            });

            console.log(`[RentriService] SUCCESS: ${response.status}`, response.data);
            return response.data;

        } catch (error: any) {
            console.error(`[RentriService] FAILED:`, error.response?.data || error.message);
            
            if (error.response) {
                console.error(`Status: ${error.response.status}`);
                console.error(`Headers: ${JSON.stringify(error.response.headers)}`);
                console.error(`Data: ${JSON.stringify(error.response.data)}`);
            }

            throw new Error(`RENTRI API Error: ${JSON.stringify(error.response?.data || error.message)}`);
        }
    }
}
