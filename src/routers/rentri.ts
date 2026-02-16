import { Router } from 'express';
import { RentriService } from '../services/rentriService';

export const rentriRouter = Router();

// Endpoint: Vidimazione (Get new FIR Number)
rentriRouter.post('/vidimate', async (req, res) => {
    try {
        const { company } = req.body;
        if (!company) {
             res.status(400).json({ error: "Missing company" });
             return;
        }
        
        const firNumber = await RentriService.vidimateFir(company);
        res.json({ firNumber });
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

        // 1. Vidimate if needed
        let firNumber = payloadFir.dati_partenza?.numero_fir;
        if (!firNumber) {
            console.log(`[Firma-FIR] Vidimating for ${societaId}...`);
            firNumber = await RentriService.vidimateFir(societaId);
            if (!payloadFir.dati_partenza) payloadFir.dati_partenza = {};
            payloadFir.dati_partenza.numero_fir = firNumber;
        }

        // 2. Create/Emit
        const result = await RentriService.createFir(societaId, payloadFir);
        res.json(result);

    } catch (e: any) {
        console.error("[Firma-FIR] Error:", e.message);
        res.status(500).json({ error: e.message });
    }
});
