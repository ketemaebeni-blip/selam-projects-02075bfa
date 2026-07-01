import { createFileRoute } from "@tanstack/react-router";

// TEMPORARY one-shot admin reset. Delete this file immediately after use.
export const Route = createFileRoute("/api/public/reset-admin-oneshot")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const body = await request.json().catch(() => ({} as any));
        // One-shot literal — this file is deleted immediately after invocation
        const TOKEN = "oneshot-reset-selam-2026-2f7a1e";
        if (body?.token !== TOKEN) {
          return new Response("Forbidden", { status: 403 });
        }
        const email = "admin@selamcake.com";
        const password = "Selam@Admin2026!";
        const { supabaseAdmin } = await import("@/integrations/supabase/client.server");

        // Find existing user
        let userId: string | null = null;
        const list = await supabaseAdmin.auth.admin.listUsers({ page: 1, perPage: 200 });
        for (const u of list.data?.users || []) {
          if ((u.email || "").toLowerCase() === email) { userId = u.id; break; }
        }
        if (userId) {
          const { error } = await supabaseAdmin.auth.admin.updateUserById(userId, {
            password, email_confirm: true,
          });
          if (error) return new Response("update failed: " + error.message, { status: 500 });
        } else {
          const { data, error } = await supabaseAdmin.auth.admin.createUser({
            email, password, email_confirm: true,
          });
          if (error || !data.user) return new Response("create failed: " + (error?.message || "unknown"), { status: 500 });
          userId = data.user.id;
        }
        // Ensure admin role
        await supabaseAdmin.from("user_roles").upsert(
          { user_id: userId, role: "admin" as any },
          { onConflict: "user_id,role" }
        );

        return new Response(JSON.stringify({ ok: true, email }), {
          status: 200, headers: { "content-type": "application/json" },
        });
      },
    },
  },
});
