// Placeholder for XML generation logic
// We should import the robust logic from previous attempts if available, 
// or rewrite a clean version using fast-xml-parser builder.

import { XMLBuilder } from 'fast-xml-parser';

export function buildRentriXml(payload: any): string {
    const builder = new XMLBuilder({
        format: true,
        ignoreAttributes: false
    });
    
    // Construct the full XML object structure here based on payload
    // For now, returning a dummy XML wrapped around payload
    const xmlObj = {
        'RentriFIR': {
            '@_version': '1.0',
            'DatiGenerali': payload.dati_generali,
            'DatiPartenza': payload.dati_partenza
        }
    };
    
    return builder.build(xmlObj);
}
