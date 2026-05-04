import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.CYBERCLAW_UI_PORT || 3001;
const API_URL = process.env.CYBERCLAW_API_URL || 'http://localhost:8000';

app.use(cors());
app.use(express.json());

// Proxy API requests to FastAPI backend
app.use('/api', createProxyMiddleware({
  target: API_URL,
  changeOrigin: true,
}));

// Proxy WebSocket to FastAPI backend
app.use('/ws', createProxyMiddleware({
  target: API_URL,
  ws: true,
  changeOrigin: true,
}));

// Serve static files in production
app.use(express.static(path.join(__dirname, 'dist')));

app.listen(PORT, () => {
  console.log(`[CyberClaw] Express proxy on http://localhost:${PORT} -> ${API_URL}`);
});
