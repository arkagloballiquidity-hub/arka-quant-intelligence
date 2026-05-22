// api/create-auth-user.js — crea usuario en Supabase Auth e inserta en tabla users
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
  // app_metadata solo escribible por service role — NO usar user_metadata como fallback
  if (caller.app_metadata?.role !== 'admin') return res.status(403).json({ error: 'Solo admins' });

  const { username, password, name, role, email } = req.body;
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
    // Setear app_metadata (solo escribible por service role — protege contra escalación de privilegios)
    await supabaseAdmin.auth.admin.updateUserById(authUserId, {
      app_metadata: { role: userRole }
    });
  }

  const { error: dbErr } = await supabaseAdmin
    .from('users')
    .upsert(
      { username, name, role: userRole, email: authEmail, auth_user_id: authUserId },
      { onConflict: 'username' }
    );

  if (dbErr) {
    return res.status(400).json({ error: 'Auth OK pero fallo DB: ' + dbErr.message });
  }

  return res.status(200).json({ user_id: authUserId, existed });
}
