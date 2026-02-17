import { Router } from 'express';
import { RentriService } from '../services/rentriService';

export const rentriRouter = Router();

// Endpoint: Vidimazione (Get new FIR Numbers)
// Body: { company: string, quantity?: number }
rentriRouter.post('/vidimate', async (req, res) => {
    try {
        const { company, quantity } = req.body;
        if (!company) {
             res.status(400).json({ error: "Missing company" });
             return;
        }
        
        const qty = quantity || 1; // Default to 1 if not specified
        
        // Returns string[] (Array of FIR numbers)
        const firNumbers = await RentriService.vidimateFir(company, qty);
        
        // Return exactly what Rentri gives (Array) or wrapped in object
        res.json({ firNumbers });
    } catch (e: any) {
        console.error("Vidimate Error:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// Endpoint: Creation (Emission)
rentriRouter.post('/create', async (req, res) => {
    try {
        const { company, payload } = req.body;
        if (!company || !payload) {
             res.status(400).json({ error: "Missing company or payload" });
             return;
        }

        const result = await RentriService.createFir(company, payload);
        res.json(result);
    } catch (e: any) {
        console.error("Create Error:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// Endpoint: Unified "Firma FIR"
rentriRouter.post('/firma-fir', async (req, res) => {
    try {
        const { societaId, payloadFir } = req.body;
        
        if (!societaId || !payloadFir) {
             res.status(400).json({ error: "Missing societaId or payloadFir" });
             return;
        }

        // 1. Vidimate if needed (Only 1 needed for a single FIR creation)
        let firNumber = payloadFir.dati_partenza?.numero_fir;
        if (!firNumber) {
            console.log(`[Firma-FIR] Vidimating for ${societaId}...`);
            const newNumbers = await RentriService.vidimateFir(societaId, 1);
            if (newNumbers && newNumbers.length > 0) {
                firNumber = newNumbers[0];
                if (!payloadFir.dati_partenza) payloadFir.dati_partenza = {};
                payloadFir.dati_partenza.numero_fir = firNumber;
            } else {
                throw new Error("Vidimation returned no numbers");
            }
        }

        // 2. Create/Emit
        const result = await RentriService.createFir(societaId, payloadFir);
        res.json(result);

    } catch (e: any) {
        console.error("[Firma-FIR] Error:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// Endpoint: Download PDF
rentriRouter.get('/pdf/:numeroFir', async (req, res) => {
    try {
        const { numeroFir } = req.params;
        const company = (req.query.company as string) || 'global';

        if (!numeroFir) {
            res.status(400).json({ error: "Missing numeroFir" });
            return;
        }

        const pdfBuffer = await RentriService.getPdf(company, numeroFir);
        
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${numeroFir}.pdf"`);
        res.send(pdfBuffer);

    } catch (e: any) {
        console.error("[PDF Download] Error:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// Endpoint: Download xFIR
rentriRouter.get('/xfir/:numeroFir', async (req, res) => {
    try {
        const { numeroFir } = req.params;
        const company = (req.query.company as string) || 'global';

        if (!numeroFir) {
            res.status(400).json({ error: "Missing numeroFir" });
            return;
        }

        const xfirContent = await RentriService.getXfir(company, numeroFir);
        
        res.setHeader('Content-Type', 'application/xml');
        res.setHeader('Content-Disposition', `attachment; filename="${numeroFir}.xml"`);
        res.send(xfirContent);

    } catch (e: any) {
        console.error("[xFIR Download] Error:", e.message);
        res.status(500).json({ error: e.message });
    }
});
