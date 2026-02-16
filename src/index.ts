import express from 'express';
import cors from 'cors';
import { rentriRouter } from './routers/rentri';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// 1. Basic Middleware (MUST BE FIRST)
app.use(cors());
// Increase limit for large Base64 payloads or XML
app.use(express.json({ limit: '50mb' })); 
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// 2. API Routes (MUST BE BEFORE STATIC FILES)
// Explicitly handle API routes first so they never fall back to HTML
console.log("Mounting /api/rentri routes...");
app.use('/api/rentri', rentriRouter);

// 3. Health Check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        env: process.env.RENTRI_ENV,
        timestamp: new Date().toISOString()
    });
});

// 4. Global Error Handler (Force JSON response)
// This catches async errors from routes if they call next(err)
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    console.error('[Server Error]', err);
    
    // Ensure we return JSON, not HTML
    if (!res.headersSent) {
        res.status(500).json({
            error: true,
            message: err.message || 'Internal Server Error',
            // Only show stack in dev/sandbox, hide in prod
            details: process.env.RENTRI_ENV !== 'PRODUCTION' ? err.stack : undefined
        });
    }
});

// 5. 404 Handler for API (Force JSON for unknown API routes)
// This ensures that if a route is missing, we don't fall through to static files
app.use('/api/*', (req, res) => {
    res.status(404).json({ 
        error: true, 
        message: `API Route not found: ${req.method} ${req.originalUrl}` 
    });
});

// 6. Static Files / Frontend (ONLY IF NEEDED)
// If you have static files (e.g. documentation), put them here.
// But for a pure API backend, this might not be needed.
// app.use(express.static('public')); 

app.listen(PORT, () => {
    console.log(`Dragon Rifiuti Sender running on port ${PORT}`);
    console.log(`Environment: ${process.env.RENTRI_ENV || 'PRODUCTION'}`);
});
