// api/create-auth-user.js — crea usuario en Supabase Auth con contraseña hasheada
import { createClient } from '@supabase/supabase-js';

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // Verificar que el llamador es un admin con sesión válida
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No autorizado' });

  const { data: { user: caller }, error: authErr } = await supabaseAdmin.auth.getUser(token);
  if (authErr || !caller) return res.status(401).json({ error: 'Sesión inválida' });
  if (caller.user_metadata?.role !== 'admin') return res.status(403).json({ error: 'Solo admins' });

  const { username, password, name, role } = req.body;
  if (!username || !password || !name) return res.status(400).json({ error: 'username, password y name son requeridos' });

  const authEmail = `${username.toLowerCase().trim()}@arkaquant.app`;

  const { data, error } = await supabaseAdmin.auth.admin.createUser({
    email: authEmail,
    password,
    email_confirm: true,
    user_metadata: { role: role || 'trader', username, display_name: name },
  });

  if (error) {
    if (error.message?.includes('already registered')) {
      const { data: list } = await supabaseAdmin.auth.admin.listUsers();
      const found = list?.users?.find(u => u.email === authEmail);
      if (found) return res.status(200).json({ user_id: found.id, existed: true });
    }
    return res.status(400).json({ error: error.message });
  }

  return res.status(200).json({ user_id: data.user.id, existed: false });
}
