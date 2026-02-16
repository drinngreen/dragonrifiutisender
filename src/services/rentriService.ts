import axios from 'axios';
import { getAuthHeaders } from '../utils/auth';
import { RENTRI_CONFIG, CompanyKey } from '../config';
import { buildRentriXml } from '../utils/xmlGenerator';

export class RentriService {

    static async vidimateFir(company: string): Promise<string> {
        // TODO: Implement actual vidimation logic or mock for now
        // If RENTRI requires a call to get a number, do it here.
        // For now, generating a mock unique number to proceed.
        const mockNumber = `FIR-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        console.log(`[RentriService] Vidimated mock number: ${mockNumber} for ${company}`);
        return mockNumber;
    }

    static async createFir(company: string, payload: any): Promise<any> {
        const config = RENTRI_CONFIG[company as CompanyKey];
        if (!config) throw new Error(`Configuration not found for company: ${company}`);

        // 1. Generate XML
        const xmlContent = buildRentriXml(payload);
        
        // 2. Get Auth Headers (Token)
        const headers = await getAuthHeaders(company as CompanyKey);

        // 3. Send to RENTRI (Mock URL or Real URL)
        // const url = 'https://api.rentri.gov.it/...'; // TODO: Real URL
        // const response = await axios.post(url, xmlContent, { headers });
        
        // MOCK RESPONSE FOR SAFETY UNTIL TESTED
        console.log(`[RentriService] Would send XML to RENTRI for ${company}`);
        
        return {
            status: 'success',
            rentriId: `RENTRI-ID-${Date.now()}`,
            firNumber: payload.dati_partenza?.numero_fir,
            xmlPreview: xmlContent.substring(0, 100) + '...'
        };
    }
}
