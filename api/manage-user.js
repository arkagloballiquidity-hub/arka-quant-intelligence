// api/manage-user.js — crea o actualiza usuarios (reemplaza create-auth-user y update-auth-password)
import { createClient } from '@supabase/supabase-js';

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

export default async function handler(req, res) {
  const origin = req.headers.origin || '';
  const ALLOWED_ORIGINS = [
    'https://arka-quant-intelligence-nine.vercel.app',
    'https://arka-quant-intelligence.vercel.app',
  ];
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  res.setHeader('Access-Control-Allow-Origin', allowed);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No autorizado' });

  const { data: { user: caller }, error: authErr } = await supabaseAdmin.auth.getUser(token);
  if (authErr || !caller) return res.status(401).json({ error: 'Sesión inválida' });
  if (caller.app_metadata?.role !== 'admin') return res.status(403).json({ error: 'Solo admins' });

  const { action, username, password, name, role, email, user_id } = req.body;

  // ── CREAR USUARIO ──────────────────────────────────────────────────
  if (action === 'create') {
    if (!username || !password || !name || !email) {
      return res.status(400).json({ error: 'username, password, name y email son requeridos' });
    }
    if (password.length < 8) return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
    const authEmail = email.toLowerCase().trim();
    const userRole = role || 'trader';

    let authUserId;
    let existed = false;

    const { data: authData, error: authCreateErr } = await supabaseAdmin.auth.admin.createUser({
      email: authEmail,
      password,
      email_confirm: true,
      user_metadata: { role: userRole, username, display_name: name },
    });

    if (authCreateErr) {
      if (authCreateErr.message?.includes('already registered')) {
        const { data: list } = await supabaseAdmin.auth.admin.listUsers({ page: 1, perPage: 1000 });
        const found = list?.users?.find(u => u.email === authEmail);
        if (found) { authUserId = found.id; existed = true; }
        else return res.status(400).json({ error: authCreateErr.message });
      } else {
        return res.status(400).json({ error: authCreateErr.message });
      }
    } else {
      authUserId = authData.user.id;
    }

    const { error: dbErr } = await supabaseAdmin
      .from('users')
      .upsert(
        { username, name, role: userRole, email: authEmail, auth_user_id: authUserId },
        { onConflict: 'username' }
      );

    if (dbErr) return res.status(400).json({ error: 'Auth OK pero fallo DB: ' + dbErr.message });
    return res.status(200).json({ user_id: authUserId, existed });
  }

  // ── ACTUALIZAR CONTRASEÑA ──────────────────────────────────────────
  if (action === 'update-password') {
    if (!password) return res.status(400).json({ error: 'password es requerido' });
    if (password.length < 8) return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });

    let targetId = user_id;

    if (!targetId && username) {
      const { data: rows } = await supabaseAdmin
        .from('users')
        .select('auth_user_id')
        .eq('username', username.toLowerCase())
        .limit(1);
      const found = rows?.[0];
      if (!found?.auth_user_id) return res.status(404).json({ error: 'Usuario sin cuenta Auth' });
      targetId = found.auth_user_id;
    }

    if (!targetId) return res.status(400).json({ error: 'user_id o username requerido' });

    const { error } = await supabaseAdmin.auth.admin.updateUserById(targetId, { password });
    if (error) return res.status(400).json({ error: error.message });
    return res.status(200).json({ success: true });
  }

  return res.status(400).json({ error: 'action requerido: create | update-password' });
}
