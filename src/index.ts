import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { rentriRouter } from './routers/rentri';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors({ origin: '*' })); // Allow all origins for now, can restrict later
app.use(express.json({ limit: '50mb' })); // Large limit for XML payloads

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'DRAGON RENTRI BACKEND', version: '1.0.0' });
});

// API Routes
app.use('/api/rentri', rentriRouter);

app.listen(PORT, () => {
  console.log(`🐉 Dragon Backend running on port ${PORT}`);
});
