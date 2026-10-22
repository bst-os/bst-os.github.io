// BST OS — akun staf: buat Owner pertama (bootstrap) dan kelola login staf (username + PIN 6 angka).
// verify_jwt mati karena setup pertama berjalan sebelum ada yang login; aksi lain memeriksa sesi & peran di bawah.
import { createClient } from "npm:@supabase/supabase-js@2";

const URL = Deno.env.get("SUPABASE_URL")!;
const SR = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const DOMAIN = "bst-os.app";
const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { ...cors, "Content-Type": "application/json" } });
const fail = (msg: string, status = 400) => json({ error: msg }, status);
const email = (u: string) => `${u}@${DOMAIN}`;
const pw = (p: string) => `bst-${p}`;
const okUser = (u: string) => /^[a-z0-9._-]{3,24}$/.test(u);
const okPin = (p: string) => /^\d{6}$/.test(p);
const ROLES = ["owner", "manager", "kasir", "dapur"];
const legacyRole = (r: string) => (r === "owner" || r === "manager" ? "owner" : "kasir");

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return fail("method", 405);
  const admin = createClient(URL, SR, { auth: { persistSession: false, autoRefreshToken: false } });
  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return fail("Body tidak valid."); }
  const action = String(body.action || "");

  const setProfile = async (id: string, p: Record<string, unknown>) => {
    const { error } = await admin.from("profiles").update(p).eq("id", id);
    if (error) throw error;
  };
  const usernameTaken = async (u: string, id: string) => {
    const { data } = await admin.from("profiles").select("id").eq("username", u).maybeSingle();
    return !!data && data.id !== id;
  };

  try {
    if (action === "bootstrap") {
      const { count } = await admin.from("profiles").select("id", { count: "exact", head: true }).eq("active", true);
      if ((count || 0) > 0) return fail("Akun pertama sudah dibuat. Masuk dengan username dan PIN.", 403);
      const username = String(body.username || "").trim().toLowerCase(), pin = String(body.pin || ""), name = String(body.name || "").trim().slice(0, 40);
      if (!okUser(username)) return fail("Username 3–24 karakter: huruf kecil, angka, titik, strip.");
      if (!okPin(pin)) return fail("PIN harus 6 angka.");
      const { data: u, error } = await admin.auth.admin.createUser({ email: email(username), password: pw(pin), email_confirm: true, user_metadata: { full_name: name } });
      if (error) return fail(/registered|exists/i.test(error.message) ? "Username sudah dipakai." : error.message);
      const { data: firstLoc } = await admin.from("locations").select("id").eq("kind", "outlet").order("sort").limit(1).maybeSingle();
      await setProfile(u.user.id, { full_name: name || "Owner", username, staff_role: "owner", role: "owner", active: true, location_id: firstLoc?.id ?? null });
      return json({ ok: true });
    }

    const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
    const { data: who } = await admin.auth.getUser(token);
    if (!who?.user) return fail("Sesi habis. Masuk lagi.", 401);
    const { data: me } = await admin.from("profiles").select("staff_role,active").eq("id", who.user.id).maybeSingle();
    const myRole = me?.active ? String(me.staff_role) : "";
    if (!["owner", "manager"].includes(myRole)) return fail("Hanya Owner atau Manager yang bisa mengatur staf.", 403);

    if (action === "save") {
      const id = String(body.id || "");
      const name = String(body.name || "").trim().slice(0, 40);
      const role = String(body.role || "kasir");
      const active = body.active !== false;
      const username = String(body.username || "").trim().toLowerCase();
      const pin = String(body.pin || "");
      const loc = body.location_id ? Number(body.location_id) : null;
      if (!name) return fail("Nama wajib diisi.");
      if (!ROLES.includes(role)) return fail("Peran tidak dikenal.");
      if (!okUser(username)) return fail("Username 3–24 karakter: huruf kecil, angka, titik, strip.");
      if (pin && !okPin(pin)) return fail("PIN harus 6 angka.");
      if (await usernameTaken(username, id)) return fail("Username sudah dipakai staf lain.");

      let prev: { staff_role: string; active: boolean; username: string } | null = null;
      if (id) {
        const { data } = await admin.from("profiles").select("staff_role,active,username").eq("id", id).maybeSingle();
        if (!data) return fail("Staf tidak ditemukan.");
        prev = data;
      }
      if ((role === "owner" || prev?.staff_role === "owner") && myRole !== "owner") return fail("Hanya Owner yang bisa mengatur akun Owner.", 403);
      if (id === who.user.id && (!active || !["owner", "manager"].includes(role))) return fail("Anda tidak bisa menonaktifkan atau menurunkan peran akun sendiri.");

      if (prev && ["owner", "manager"].includes(prev.staff_role) && prev.active && (!["owner", "manager"].includes(role) || !active)) {
        const { count } = await admin.from("profiles").select("id", { count: "exact", head: true })
          .neq("id", id).in("staff_role", ["owner", "manager"]).eq("active", true);
        if (!count) return fail("Harus ada minimal satu Owner atau Manager aktif.");
      }

      if (id) {
        const upd: Record<string, unknown> = { ban_duration: active ? "none" : "876000h", user_metadata: { full_name: name } };
        if (username !== prev!.username) upd.email = email(username);
        if (pin) upd.password = pw(pin);
        const { error } = await admin.auth.admin.updateUserById(id, upd);
        if (error) return fail(error.message);
        await setProfile(id, { full_name: name, username, staff_role: role, role: legacyRole(role), active, email: email(username), location_id: loc });
        return json({ ok: true, id });
      }
      if (!pin) return fail("Isi PIN 6 angka untuk akun baru.");
      const { data: u, error } = await admin.auth.admin.createUser({ email: email(username), password: pw(pin), email_confirm: true, user_metadata: { full_name: name }, ban_duration: active ? "none" : "876000h" });
      if (error) return fail(/registered|exists/i.test(error.message) ? "Username sudah dipakai." : error.message);
      await setProfile(u.user.id, { full_name: name, username, staff_role: role, role: legacyRole(role), active, location_id: loc });
      return json({ ok: true, id: u.user.id });
    }
    return fail("Aksi tidak dikenal.");
  } catch (e) {
    console.error(e);
    return fail("Server error: " + (e instanceof Error ? e.message : String(e)), 500);
  }
});
