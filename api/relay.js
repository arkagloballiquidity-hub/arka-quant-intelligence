// api/relay.js
// Proxy seguro hacia el relay de Railway — el API key nunca llega al navegador
// El llamador se autentica con su JWT de Supabase; este endpoint agrega el key del relay

import { createClient } from '@supabase/supabase-js';

const RELAY_ORIGIN = 'https://arka-quant-relay-production.up.railway.app';
const RELAY_KEY    = process.env.ARKA_RELAY_KEY;

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', 'https://arka-quant-intelligence.vercel.app');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!['GET','POST'].includes(req.method)) return res.status(405).json({ error: 'Method not allowed' });

  // Verificar sesión Supabase del llamador
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return res.status(401).json({ error: 'No autorizado' });
  const token = authHeader.split(' ')[1];
  const { data: { user }, error: authErr } = await supabaseAdmin.auth.getUser(token);
  if (authErr || !user) return res.status(401).json({ error: 'Sesión inválida' });

  // Extraer endpoint destino (ej: /api/technicals, /yahoo)
  const { ep, ...queryParams } = req.query;
  const allowedPrefixes = ['/api/', '/yahoo'];
  if (!ep || !allowedPrefixes.some(p => ep.startsWith(p))) {
    return res.status(400).json({ error: 'ep inválido' });
  }

  // Construir URL del relay con los parámetros restantes
  const targetUrl = new URL(RELAY_ORIGIN + ep);
  Object.entries(queryParams).forEach(([k, v]) => targetUrl.searchParams.append(k, v));

  // Preparar opciones del fetch
  const fetchOptions = {
    method: req.method,
    headers: {
      'Authorization': `Bearer ${RELAY_KEY}`,
      'Content-Type': 'application/json',
    },
  };
  if (req.method === 'POST' && req.body) {
    fetchOptions.body = JSON.stringify(req.body);
  }

  try {
    const upstream = await fetch(targetUrl.toString(), fetchOptions);
    const data = await upstream.json();
    return res.status(upstream.status).json(data);
  } catch (err) {
    return res.status(502).json({ error: 'Error comunicando con el relay', detail: err.message });
  }
}
