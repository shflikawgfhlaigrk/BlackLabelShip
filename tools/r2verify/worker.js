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
//
// KEYS ARRIVE BASE64URL-ENCODED (?b64=), NOT AS A PERCENT-ENCODED ?key=.
// Percent-encoding CANNOT get a backup key past the edge, and that was proven the hard way on
// 2026-07-12: Cloudflare normalises (decodes) the query string BEFORE the WAF evaluates it, so a
// dot in `.dump` / `.tar.gz` re-materialises no matter how it is escaped. Every variant was tried
// against the live bucket — raw -> 1042, quote(safe='') -> 1104, %2E-escaped dots -> 1042,
// every-byte-percent-encoded -> 1042. All four bounced at the edge, and the WAF's own error page
// ("error code: 1042\n", exactly 17 bytes) landed in the output file, so a COMPLETE and byte-exact
// off-site set read as 100% MISSING. base64url's alphabet is [A-Za-z0-9_-] — it has no dot and no
// slash, so there is nothing for the WAF to normalise and nothing for it to match.

const json = (o, status = 200) =>
  new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });

const decodeKey = (b64) => {
  const b = b64.replace(/-/g, "+").replace(/_/g, "/");
  return new TextDecoder().decode(
    Uint8Array.from(atob(b), (c) => c.charCodeAt(0)),
  );
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.searchParams.get("t") !== env.TOKEN) return json({ error: "forbidden" }, 403);

    const b64 = url.searchParams.get("b64");
    if (!b64) return json({ error: "b64 key required" }, 400);
    let key;
    try {
      key = decodeKey(b64);
    } catch {
      return json({ error: "b64 key undecodable" }, 400);
    }

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

    // /sha — HASH THE OBJECT INSIDE CLOUDFLARE AND RETURN ONLY THE DIGEST.
    //
    // This, not /o, is the restore-proof. Dragging 3.7 GiB back through the edge to sha256 it locally
    // is what kept failing: multi-hundred-MiB octet-stream reads bounce intermittently with Cloudflare
    // "error code: 1042" (HTTP 404 + a 17-byte body) — even while /h on the very same key answers
    // present:true in the same run. A restore-proof that flakes on the transport reports a healthy
    // backup as a lost one, which is the one thing a backup verifier must never do.
    //
    // DigestStream hashes the R2 body as it streams, so nothing is ever buffered and nothing crosses
    // the network but 64 hex chars. `?parts=N` reproduces the RESTORE itself: the parts are piped into
    // ONE digest in lexical order (aa, ab, …), so the hash returned is the hash of the reassembled
    // original file — exactly what `cat *.part.* > original` would produce locally. The digest is
    // computed by Cloudflare over the bytes R2 actually holds, then compared against the LOCAL
    // SHA256SUMS. That is a genuine integrity proof of the off-site copy, not a proof about a cache.
    if (url.pathname === "/sha") {
      const parts = parseInt(url.searchParams.get("parts") || "0", 10);
      const keys = [];
      if (parts > 0) {
        const az = "abcdefghijklmnopqrstuvwxyz";
        for (let i = 0; i < parts; i++) {
          const suf = az[Math.floor(i / 26)] + az[i % 26];
          keys.push(`${key}.parts/${key.split("/").pop()}.part.${suf}`);
        }
      } else {
        keys.push(key);
      }

      const digest = new crypto.DigestStream("SHA-256");
      const writer = digest.getWriter();
      let total = 0;
      for (const k of keys) {
        const obj = await env.BACKUPS.get(k);
        if (!obj) {
          await writer.abort("missing");
          return json({ key: k, present: false, error: "object missing" }, 404);
        }
        // Pump this object's body into the shared digest before moving to the next part.
        for await (const chunk of obj.body) {
          total += chunk.byteLength;
          await writer.write(chunk);
        }
      }
      await writer.close();
      const hex = [...new Uint8Array(await digest.digest)]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      return json({ key, parts: keys.length, bytes: total, sha256: hex });
    }

    return json({ error: "not found" }, 404);
  },
};
