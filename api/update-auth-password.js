// api/update-auth-password.js — actualiza contraseña de usuario existente
import { createClient } from '@supabase/supabase-js';

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

export default async function handler(req, res) {
  const origin = req.headers.origin || '';
  const allowed = /^https:\/\/arka-quant-intelligence(-[a-z0-9]+)?\.vercel\.app$/.test(origin) ? origin : 'https://arka-quant-intelligence-nine.vercel.app';
  res.setHeader('Access-Control-Allow-Origin', allowed);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No autorizado' });

  const { data: { user: caller }, error: authErr } = await supabaseAdmin.auth.getUser(token);
  if (authErr || !caller) return res.status(401).json({ error: 'Sesión inválida' });
  const callerRole = caller.app_metadata?.role || caller.user_metadata?.role;
  if (callerRole !== 'admin') return res.status(403).json({ error: 'Solo admins' });

  const { user_id, username, password } = req.body;
  if (!password) return res.status(400).json({ error: 'password es requerido' });

  let targetId = user_id;

  // Si no viene user_id, buscar por username en la tabla users (usando auth_user_id)
  if (!targetId && username) {
    const { data: rows } = await supabaseAdmin
      .from('users')
      .select('auth_user_id')
      .eq('username', username.toLowerCase())
      .limit(1);
    const found = rows?.[0];
    if (!found?.auth_user_id) return res.status(404).json({ error: 'Usuario no encontrado o sin cuenta Auth' });
    targetId = found.auth_user_id;
  }

  if (!targetId) return res.status(400).json({ error: 'user_id o username requerido' });

  const { error } = await supabaseAdmin.auth.admin.updateUserById(targetId, { password });
  if (error) return res.status(400).json({ error: error.message });

  return res.status(200).json({ success: true });
}
