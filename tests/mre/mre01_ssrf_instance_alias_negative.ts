// MRE-01b - paired negative for mre01_ssrf_instance_alias (SAFE).
// Absolute and protocol-relative targets are rejected before the request,
// so baseURL always wins and the credential never leaves for an attacker
// host (the CVE-2025-27152 remediation, axios 1.8.2).
//
// EXPECTED: 0 advisories. ACTUAL today: 0 advisories (vacuously - the
// positive is silent too, so the family cannot separate and the bundler
// learns nothing from this pair; see docs/mre/README.md, learn defect L1).

import axios from "axios";

const client = axios.create({
    baseURL: "http://directory.internal/api/v1/users/",
    headers: { "X-API-KEY": process.env.DIRECTORY_API_KEY ?? "" },
});

export async function getUser(req: any, res: any): Promise<void> {
    const userId = String(req.params.id);

    if (/^[a-z][a-z0-9+.-]*:/i.test(userId) || userId.startsWith("//")) {
        res.status(400).send("user id must be a relative path segment");
        return;
    }

    const resp = await client.get(userId);
    res.json(resp.data);
}
