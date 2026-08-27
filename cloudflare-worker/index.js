/**
 * GARUDA CT Log Edge Filter Worker
 *
 * Intercepts Certificate Transparency (CT) log streaming events at the Cloudflare edge
 * and performs sub-millisecond keyword pattern matching against Tier-1 national infrastructure
 * keywords before dispatching candidates to the GARUDA API.
 */

export default {
  async fetch(request, env) {
    if (request.method !== "POST") {
      return new Response("OK", { status: 200 });
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return new Response("Invalid JSON", { status: 400 });
    }

    // Extract domain from CertStream / CT Log webhook payload
    const domain = body.data?.leaf_cert?.all_domains?.[0] || body.domain;
    if (!domain) {
      return new Response("OK", { status: 200 });
    }

    const domainLower = domain.toLowerCase();

    // Fast keyword filter at edge (no DB access)
    const tier1Raw = env.TIER1_PATTERNS || "mod,gov,nic,army,drdo,isro,mil,defence,hal,bel,barc,ntro,dae";
    const tier1Patterns = tier1Raw.split(",").map((kw) => kw.trim().toLowerCase()).filter(Boolean);

    const hasTier1 = tier1Patterns.some((kw) => domainLower.includes(kw));
    if (!hasTier1) {
      return new Response("OK", { status: 200 });
    }

    // Forward matching candidate to GARUDA API for full ML & graph pipeline
    const apiUrl = env.GARUDA_API_URL || "https://garuda.vercel.app";
    const cronSecret = env.CRON_SECRET || "";

    try {
      await fetch(`${apiUrl}/api/collect/webhook`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${cronSecret}`,
        },
        body: JSON.stringify({
          domain: domainLower,
          source: "cf_worker",
          timestamp: new Date().toISOString(),
          cert_data: body.data?.leaf_cert || null,
        }),
      });
    } catch (err) {
      // Edge worker swallows upstream error to maintain 200 OK webhook response
    }

    return new Response("OK", { status: 200 });
  },
};
