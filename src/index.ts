import express from 'express';
import cors from 'cors';
import { rentriRouter } from './routers/rentri';
import dotenv from 'dotenv';
import { startBridge } from './bridgeStarter'; // Import Bridge Starter

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// 0. Start C# Bridge Service (Sidecar)
startBridge();

// 1. Basic Middleware
app.use(cors({
    origin: ['https://dragonrifiutiapp.sbs', 'http://localhost:5173', 'http://localhost:3000'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// 2. Health Check (Pure JSON)
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// 3. API Routes
console.log("Mounting /api/rentri routes...");
app.use('/api/rentri', rentriRouter);

// 4. Global Error Handler (Pure JSON)
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    console.error('[Server Error]', err);
    if (!res.headersSent) {
        res.status(500).json({ 
            error: true, 
            message: err.message || 'Internal Server Error' 
        });
    }
});

// 5. 404 Handler (Pure JSON) - NO HTML FALLBACK
app.use((req, res) => {
    res.status(404).json({ 
        error: true, 
        message: `Route not found: ${req.method} ${req.originalUrl}` 
    });
});

app.listen(PORT, () => {
    console.log(`Dragon Rifiuti Sender (Pure API) running on port ${PORT}`);
});
