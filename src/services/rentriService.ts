import { getRentriClient } from '../utils/clientFactory';
import { RENTRI_CONFIG, CompanyKey } from '../config';
import { buildRentriXml } from '../utils/xmlGenerator';

export class RentriService {

    static async vidimateFir(company: string): Promise<string> {
        // TODO: La vidimazione reale richiede una chiamata specifica. 
        // Per ora manteniamo il mock per non bloccare tutto se l'endpoint è diverso.
        // Se hai l'endpoint corretto per vidimare, fammelo sapere.
        const mockNumber = `FIR-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        console.log(`[RentriService] Vidimated mock number: ${mockNumber} for ${company}`);
        return mockNumber;
    }

    static async createFir(company: string, payload: any): Promise<any> {
        // 1. Generate XML
        const xmlContent = buildRentriXml(payload);
        
        // 2. Get Real mTLS Client
        const client = getRentriClient(company as CompanyKey);

        // 3. Send to RENTRI - REAL CALL
        // Endpoint: /fir/emissione (DA CONFERMARE SULLA DOC RENTRI)
        // Se non è questo, cambialo qui o metti una variabile RENTRI_ENDPOINT_EMISSIONE
        const endpoint = '/fir/emissione'; 
        
        console.log(`[RentriService] SENDING REAL XML to ${client.defaults.baseURL}${endpoint}`);
        
        try {
            const response = await client.post(endpoint, xmlContent);

            console.log(`[RentriService] SUCCESS: ${response.status}`, response.data);
            return response.data;

        } catch (error: any) {
            console.error(`[RentriService] FAILED:`, error.response?.data || error.message);
            
            // Log full error details for debugging
            if (error.code) console.error(`Code: ${error.code}`);
            if (error.response) {
                console.error(`Status: ${error.response.status}`);
                console.error(`Data: ${JSON.stringify(error.response.data)}`);
            }

            throw new Error(`RENTRI API Error: ${JSON.stringify(error.response?.data || error.message)}`);
        }
    }
}
