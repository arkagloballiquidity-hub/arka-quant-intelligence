// api/update-auth-password.js — actualiza contraseña de usuario existente
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

  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No autorizado' });

  const { data: { user: caller }, error: authErr } = await supabaseAdmin.auth.getUser(token);
  if (authErr || !caller) return res.status(401).json({ error: 'Sesión inválida' });
  if (caller.user_metadata?.role !== 'admin') return res.status(403).json({ error: 'Solo admins' });

  const { user_id, username, password } = req.body;
  if (!password) return res.status(400).json({ error: 'password es requerido' });

  let targetId = user_id;
  if (!targetId && username) {
    const authEmail = `${username.toLowerCase()}@arkaquant.app`;
    const { data: list } = await supabaseAdmin.auth.admin.listUsers();
    const found = list?.users?.find(u => u.email === authEmail);
    if (!found) return res.status(404).json({ error: 'Usuario no encontrado' });
    targetId = found.id;
  }

  if (!targetId) return res.status(400).json({ error: 'user_id o username requerido' });

  const { error } = await supabaseAdmin.auth.admin.updateUserById(targetId, { password });
  if (error) return res.status(400).json({ error: error.message });

  return res.status(200).json({ success: true });
}
