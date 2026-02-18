import https from 'https';
import crypto from 'crypto';
import fs from 'fs';
import axios from 'axios'; // Top-level import
import { RENTRI_CONFIG, CompanyKey } from '../config';
import { buildRentriXml } from '../utils/xmlGenerator';
import { signAgidPayload, generateAuthJwt } from '../utils/agid_v2';
import { getRentriClient } from '../utils/clientFactory';

// BRIDGE CONFIGURATION
const BRIDGE_URL = 'http://localhost:8765/send-rentri';

function getP12Filename(company: string): string {
    switch(company.toLowerCase()) {
        case 'global': return 'certificato.p12';
        case 'multy': return 'multyproget.p12';
        case 'niyol': return 'niyol.p12';
        default: return 'certificato.p12';
    }
}

async function callBridge(targetUrl: string, payload: string, company: string): Promise<any> {
    const p12Filename = getP12Filename(company);
    const bridgeBody = {
        url: targetUrl,
        payload: payload,
        filename: p12Filename,
        issuer: "" // Bridge auto-detect
    };
    
    console.log(`[RentriService] Bridge Call -> ${targetUrl} (Company: ${company})`);
    try {
        const res = await axios.post(BRIDGE_URL, bridgeBody);
        if (res.data && res.data.success) {
            const innerData = typeof res.data.data === 'string' ? JSON.parse(res.data.data) : res.data.data;
            return innerData;
        } else {
            throw new Error(`Bridge Error: ${JSON.stringify(res.data)}`);
        }
    } catch (error: any) {
        console.error(`[RentriService] Bridge Connection Error: ${error.message}`);
        if (error.response) console.error(`[RentriService] Bridge Details:`, error.response.data);
        throw error;
    }
}

export class RentriService {

    /**
     * VIDIMAZIONE FIR via BRIDGE
     */
    static async vidimateFir(company: string, quantity: number = 1): Promise<string[]> {
        console.log(`[RentriService] Vidimation via BRIDGE for ${company} (Qty: ${quantity})...`);
        
        const config = RENTRI_CONFIG[company as CompanyKey];
        if (!config) throw new Error(`Config not found for company: ${company}`);

        let blockCode = 'FMGWB'; 
        switch(company.toLowerCase()) {
            case 'multy': blockCode = 'ZRZXR'; break;
            case 'niyol': blockCode = 'BPJMG'; break;
            default: blockCode = 'FMGWB'; // Global Reco and fallback
        }

        const isTest = config.apiBase.includes('test') || config.apiBase.includes('demo');
        const hostname = isTest ? 'rentri.gov.it' : 'api.rentri.gov.it';
        const path = `/vidimazione-formulari/v1.0/${blockCode}`;
        const targetUrl = `https://${hostname}${path}`;

        const payload = JSON.stringify({ quantita: quantity });

        try {
            const data = await callBridge(targetUrl, payload, company);
            console.log(`[RentriService] Vidimation Success:`, JSON.stringify(data));
            
            if (Array.isArray(data)) return data;
            else if (data.numero_fir) return [data.numero_fir];
            else return [];
        } catch (e: any) {
            throw new Error(`Vidimation Failed: ${e.message}`);
        }
    }

    /**
     * CREATE FIR (EMISSIONE) via BRIDGE
     */
    static async createFir(company: string, payload: any): Promise<any> {
        console.log(`[RentriService] Create FIR via BRIDGE for ${company}...`);
        
        const config = RENTRI_CONFIG[company as CompanyKey];
        if (!config) throw new Error(`Config not found for company: ${company}`);

        // Construct URL for Emission
        const isTest = config.apiBase.includes('test') || config.apiBase.includes('demo');
        const hostname = isTest ? 'rentri.gov.it' : 'api.rentri.gov.it';
        // Base path for formulari is usually /formulari/v1.0
        const path = '/formulari/v1.0';
        const targetUrl = `https://${hostname}${path}`;

        const xmlContent = buildRentriXml(payload);
        return await callBridge(targetUrl, xmlContent, company);
    }

    // Keep GET methods simple or migrate later.
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
