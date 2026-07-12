// THE ONLY TRUSTWORTHY WAY TO READ R2.
//
// `wrangler r2 object get --remote` SERVES STALE CACHED READS. Proven 2026-07-12: it returned
// old-b6 bytes for a live-b7 key, and certified a DELETED object as PRESENT across four deletes and
// an overwrite — exit 0 every time. Writes land fine; only READS lie. Any restore-proof or ship-proof
// built on that CLI read is unsound, which is why backup_offsite_verify.sh's ALL-PASS could not be
// trusted. An R2 *binding* read goes straight to the bucket with no CLI cache in the path.
//
// This Worker is THROWAWAY: backup_offsite_verify.sh deploys it, reads through it, and deletes it in
// a trap — so no endpoint that can serve backup objects outlives a verification run. It is also
// token-gated. The objects are already encrypted at rest (.enc), and this Worker never lists the
// bucket: you can only read a key you already know.
//
// Callers MUST percent-encode dots in the key (foo%2Ezip). A literal dot in the query string trips
// Cloudflare WAF rule 1104 and the request never reaches this code.

const json = (o, status = 200) =>
  new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.searchParams.get("t") !== env.TOKEN) return json({ error: "forbidden" }, 403);

    const key = url.searchParams.get("key");
    if (!key) return json({ error: "key required" }, 400);

    // HEAD: existence + size + etag, without moving the bytes.
    if (url.pathname === "/h") {
      const obj = await env.BACKUPS.head(key);
      if (!obj) return json({ key, present: false }, 404);
      return json({ key, present: true, size: obj.size, etag: obj.etag });
    }

    // GET: stream the object body back so the caller can sha256 it locally. Streaming (not
    // buffering) keeps a 290 MiB chunk well inside the Worker memory limit.
    if (url.pathname === "/o") {
      const obj = await env.BACKUPS.get(key);
      if (!obj) return new Response("not found", { status: 404 });
      return new Response(obj.body, {
        headers: {
          "content-type": "application/octet-stream",
          "content-length": String(obj.size),
        },
      });
    }

    return json({ error: "not found" }, 404);
  },
};
