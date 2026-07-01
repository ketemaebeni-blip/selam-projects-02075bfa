import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

const ALLOWED_MIME = ["image/jpeg", "image/png", "image/webp", "image/gif"] as const;
const MAX_BYTES = 5 * 1024 * 1024; // 5 MB
const MAGIC: Array<{ mime: (typeof ALLOWED_MIME)[number]; bytes: number[] }> = [
  { mime: "image/jpeg", bytes: [0xff, 0xd8, 0xff] },
  { mime: "image/png", bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { mime: "image/gif", bytes: [0x47, 0x49, 0x46, 0x38] }, // GIF8
  // WEBP: "RIFF"...."WEBP" — checked separately
];

function detectMime(buf: Uint8Array): string | null {
  for (const m of MAGIC) {
    if (buf.length >= m.bytes.length && m.bytes.every((b, i) => buf[i] === b)) return m.mime;
  }
  if (
    buf.length >= 12 &&
    buf[0] === 0x52 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x46 &&
    buf[8] === 0x57 && buf[9] === 0x45 && buf[10] === 0x42 && buf[11] === 0x50
  ) return "image/webp";
  return null;
}

const InputSchema = z.object({
  scope: z.enum(["items", "categories"]),
  key: z.string().trim().min(1).max(80).regex(/^[a-zA-Z0-9._-]+$/, "invalid key"),
  contentType: z.string().min(1),
  base64: z.string().min(1),
});

export const uploadAdminImage = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: unknown) => InputSchema.parse(data))
  .handler(async ({ data, context }) => {
    // Authorize: admin only
    const { data: isAdmin, error: roleErr } = await context.supabase
      .rpc("has_role", { _user_id: context.userId, _role: "admin" as any });
    if (roleErr) throw new Error("Authorization check failed");
    if (!isAdmin) throw new Error("Forbidden: admin role required");

    // Declared content type
    if (!ALLOWED_MIME.includes(data.contentType as any)) {
      throw new Error(`Unsupported content type "${data.contentType}". Allowed: JPG, PNG, WEBP, GIF.`);
    }

    // Decode
    let buf: Buffer;
    try {
      buf = Buffer.from(data.base64, "base64");
    } catch {
      throw new Error("Invalid file encoding.");
    }
    if (buf.byteLength === 0) throw new Error("Empty file.");
    if (buf.byteLength > MAX_BYTES) {
      throw new Error(`File too large (${(buf.byteLength / (1024 * 1024)).toFixed(2)} MB). Max 5 MB.`);
    }

    // Sniff magic bytes and require declared type to match
    const sniffed = detectMime(buf);
    if (!sniffed) throw new Error("File is not a valid JPG, PNG, WEBP, or GIF image.");
    if (sniffed !== data.contentType) {
      throw new Error(`File contents (${sniffed}) do not match declared type (${data.contentType}).`);
    }

    const extMap: Record<string, string> = {
      "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif",
    };
    const ext = extMap[sniffed];
    const folder = data.scope === "items" ? "items" : "categories";
    const path = `${folder}/${data.key}-${Date.now()}.${ext}`;

    // Use service-role admin client for the actual write
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { error: upErr } = await supabaseAdmin.storage
      .from("cake-images")
      .upload(path, buf, { upsert: true, contentType: sniffed });
    if (upErr) throw new Error(`Upload failed: ${upErr.message}`);

    const { data: signed, error: sErr } = await supabaseAdmin.storage
      .from("cake-images")
      .createSignedUrl(path, 60 * 60 * 24 * 365 * 10);
    if (sErr || !signed) throw new Error(`Could not create signed URL: ${sErr?.message || "unknown"}`);

    return { path, url: signed.signedUrl };
  });
