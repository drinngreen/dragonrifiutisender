import { getRentriClient } from '../utils/clientFactory';
import { RENTRI_CONFIG, CompanyKey } from '../config';
import { buildRentriXml } from '../utils/xmlGenerator';
import { signAgidPayload } from '../utils/agid_v2';

export class RentriService {

    static async vidimateFir(company: string): Promise<string> {
        const mockNumber = `FIR-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        return mockNumber;
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
        const endpoint = '/fir/emissione'; 
        
        console.log(`[RentriService] SENDING REAL XML to ${client.defaults.baseURL}${endpoint}`);
        
        // DEBUG HEADERS
        const headers = {
            'Agid-JWT-Signature': agidSignature,
            'Content-Type': 'application/xml',
            'Accept': 'application/xml'
        };
        
        console.log(`[RentriService] Request Headers Debug:`);
        console.log(`- Agid-JWT-Signature Length: ${headers['Agid-JWT-Signature'].length}`);
        console.log(`- Content-Type: ${headers['Content-Type']}`);

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
}
