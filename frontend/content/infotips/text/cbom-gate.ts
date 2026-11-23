/**
 * (i) tip text of the "cbom-gate" area (ids: cbom.gate.*), loaded on demand by content/infotips/load.ts: Settings >
 * CBOM policy gate (components/cicd/CbomGatePolicyPage.tsx, SOW S1). The label of each tip is in
 * content/infotips/labels.ts; the rules for the text are in content/infotips/index.ts.
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // src: backend/utilities/cicd/gate_policy_store.py:29-43, frontend/components/cicd/CbomGatePolicyPage.tsx:380 — integration, else team, else default
  "cbom.gate.team": {
    what: "The policy POST /cicd/cbom/scan applies to every CBOM CI/CD integration of the team that has no policy of its own. Without one, the default applies: NIST SP 800-131A Rev. 2 minimums and banned algorithms, with 112-bit keys, quantum-vulnerable and deprecated algorithms reported as warnings.",
    why: "Decides which crypto findings stop a release in every pipeline that runs the CBOM scan.",
    example: "Team strict: RSA 3072, EC 384, quantum-vulnerable fails the build.",
  },
  // src: backend/routers/cbom_gate_policy.py:95-121, frontend/components/cicd/CbomGatePolicyPage.tsx:393 — per-integration override
  "cbom.gate.integrations": {
    what: "Each CBOM CI/CD integration follows the team policy unless it is given its own; its own policy replaces the team policy for that pipeline only.",
    why: "A legacy application can keep dated exceptions without weakening the gate for everyone else.",
    example: "payments-legacy has its own policy with an HSM exception until March.",
  },
  // src: backend/utilities/cicd/gate_policy.py:92-131, frontend/components/cicd/CbomGatePolicyPage.tsx:144 — three presets
  "cbom.gate.preset": {
    what: "Fills the form from a preset: NIST SP 800-131A Rev. 2 (the default: RSA/DSA/DH 2048, EC 224, AES-128), SP 800-131A from 2031 (the 128-bit floor: RSA/DSA/DH 3072, EC 256) or CNSA 2.0 (RSA/DH 3072, EC 384, AES-256, SHA-1 banned, quantum-vulnerable and deprecated fail). Your exceptions are kept; nothing is saved until Save policy.",
    why: "Starts from a recognised baseline instead of picking numbers by hand.",
    example: "CNSA 2.0 for a system that handles national-security data.",
  },
  // src: backend/utilities/cicd/gate_policy.py:480-500, frontend/components/cicd/CbomGatePolicyPage.tsx:160 — 1-80 characters
  "cbom.gate.name": {
    what: "A name of up to 80 characters, shown in every CI verdict and on the CI/CD log next to the policy's digest.",
    why: "Tells a developer whose build failed which policy judged it.",
    example: "Payments: CNSA 2.0 with HSM exception.",
  },
  // src: backend/utilities/cicd/gate_policy.py:134-137,685-688, frontend/components/cicd/CbomGatePolicyPage.tsx:164 — off, warn or fail
  "cbom.gate.quantum": {
    what: "Findings on quantum-vulnerable public-key algorithms (RSA, DSA, DH, elliptic curves). Off: not reported; Warn: listed as warnings and the build passes; Fail: the build fails.",
    why: "CNSA 2.0 and NIST IR 8547 deprecate these after 2030 and disallow them after 2035; failing early forces the migration plan.",
    example: "Warn during the transition, Fail from the date your plan sets.",
  },
  // src: backend/utilities/cicd/gate_policy.py:147-170,338-352, frontend/components/cicd/CbomGatePolicyPage.tsx:172 — SHA-1 outside HMAC, DSA, PKCS #1 v1.5 key transport
  "cbom.gate.deprecated": {
    what: "Algorithms NIST SP 800-131A Rev. 2 and FIPS 186-5 have retired but not banned outright: SHA-1 outside HMAC, DSA signatures and RSA PKCS #1 v1.5 key transport. Off, Warn or Fail, like the quantum setting.",
    why: "They are still found in older code and certificates, and auditors ask for a dated plan to remove them.",
    example: "SHA1withRSA in a signing helper reported as a warning.",
  },
  // src: backend/utilities/cicd/gate_policy.py:66-72,107,646-669, frontend/components/cicd/CbomGatePolicyPage.tsx:45 — 1024 to 16384; 2048 warns until 2030
  "cbom.gate.min_rsa": {
    what: "The smallest RSA modulus allowed, 1024 to 16384 bits; a key below it fails the build. A key at or above it but below 3072 bits passes with a warning that SP 800-131A allows it only through 2030. A key whose size the scan could not read is not judged.",
    why: "SP 800-131A disallows RSA below 2048 bits now and below 3072 bits from 2031.",
    example: "2048 (default), 3072 for the 2031 floor and CNSA 2.0.",
  },
  // src: backend/utilities/cicd/gate_policy.py:66-72,107,646-669, frontend/components/cicd/CbomGatePolicyPage.tsx:46 — 1024 to 16384
  "cbom.gate.min_dsa": {
    what: "The smallest DSA key allowed, 1024 to 16384 bits. A key below it fails the build; 2048-bit keys warn about the 2030 deadline, and DSA itself is also listed under deprecated.",
    why: "DSA below 2048 bits is disallowed by SP 800-131A.",
    example: "2048.",
  },
  // src: backend/utilities/cicd/gate_policy.py:66-72,107,646-669, frontend/components/cicd/CbomGatePolicyPage.tsx:47 — includes ffdhe groups
  "cbom.gate.min_dh": {
    what: "The smallest finite-field Diffie-Hellman group allowed, 1024 to 16384 bits (named groups such as ffdhe2048 count by their size). 2048-bit groups warn about the 2030 deadline.",
    why: "Small DH groups are breakable and are disallowed below 2048 bits by SP 800-131A.",
    example: "2048, or 3072 for CNSA 2.0.",
  },
  // src: backend/utilities/cicd/gate_policy.py:92-98,107,260-269,646-669, frontend/components/cicd/CbomGatePolicyPage.tsx:48 — curve size; default 224
  "cbom.gate.min_ec": {
    what: "The smallest elliptic curve allowed, 160 to 571 bits, read from the curve (P-224 is 224, P-256 and secp256r1 256; X25519 and Ed25519 count as 256). The default 224 follows SP 800-131A Rev. 2; P-224 then passes with a warning that it is allowed only through 2030.",
    why: "Curves below 224 bits are disallowed now and below 256 bits from 2031; CNSA 2.0 asks for P-384.",
    example: "224 (default), 256 from 2031, 384 for CNSA 2.0.",
  },
  // src: backend/utilities/cicd/gate_policy.py:66-72,271-326, frontend/components/cicd/CbomGatePolicyPage.tsx:49 — 56 to 256
  "cbom.gate.min_symmetric": {
    what: "The smallest symmetric key allowed, 56 to 256 bits (AES-128 is 128, 3DES counts as 112, ChaCha20 as 256).",
    why: "Short symmetric keys can be brute-forced; CNSA 2.0 requires AES-256.",
    example: "128 (default), 256 for CNSA 2.0.",
  },
  // src: backend/utilities/cicd/gate_policy.py:140-144,329-335, frontend/components/cicd/CbomGatePolicyPage.tsx:192 — names and aliases
  "cbom.gate.banned": {
    what: "Algorithm names that fail the build wherever they are used, including inside a longer name (HMAC-MD5, MD5withRSA). 3DES also matches TDEA, DESede and TripleDES. A banned algorithm is not judged again on key size.",
    why: "Some algorithms are broken whatever the key size, so any use must stop the release.",
    example: "MD2, MD4, MD5, DES, 3DES, RC2, RC4.",
  },
  // src: backend/utilities/cicd/gate_policy.py:79-89,630-638, frontend/components/cicd/CbomGatePolicyPage.tsx:199 — the CLI's high codes by default
  "cbom.gate.block_codes": {
    what: "Finding codes of the CBOM scanner that fail the build; each blocked code is reported as its own rule. By default the high set: weak algorithm or key, ECB, hard-coded key, static IV, reused nonce, weak RNG, weak padding, disabled certificate verification and vulnerable crypto libraries.",
    why: "Covers misuse that is not about the algorithm itself, such as a key written in the source code.",
    example: "Untick VULNERABLE_CRYPTO_LIBRARY if a separate SCA gate already fails on it.",
  },
  // src: backend/utilities/cicd/gate_policy.py:381-478,599-620, frontend/components/cicd/CbomGatePolicyPage.tsx:213 — one rule, one target, bounded location, reason, expiry
  "cbom.gate.exceptions": {
    what: "Narrow, dated waivers: each names one rule, the finding code or algorithm it covers, a bounded location, a reason and an expiry at most 366 days ahead. A waived finding is listed in the verdict with its reason; after the expiry it fails again and the verdict lists the expired exception.",
    why: "A known, scheduled fix should not block every release, but it must not hide other findings or be forgotten.",
    example: "Key below the minimum size, RSA-1024, vendor/hsm/* until 2027-01-31.",
  },
  // src: backend/utilities/cicd/gate_policy.py:411-412,604-614, frontend/components/cicd/CbomGatePolicyPage.tsx:222 — exactly one rule
  "cbom.gate.exc.rule": {
    what: "The one rule the exception waives. There is no \"every rule\" choice: waiving the key size still lets a hard-coded key or a banned algorithm in the same place fail the build.",
    why: "Keeps an exception from turning off the gate for a whole file or folder.",
    example: "Key below the minimum size.",
  },
  // src: backend/utilities/cicd/gate_policy.py:413-428,614-616, frontend/components/cicd/CbomGatePolicyPage.tsx:223 — required for every rule but finding_code
  "cbom.gate.exc.algorithm": {
    what: "For every rule but Blocked finding code: the algorithm the exception covers, matched like a banned name (RSA-1024 covers RSA-1024 only).",
    why: "Keeps the waiver as narrow as the problem.",
    example: "RSA-1024.",
  },
  // src: backend/utilities/cicd/gate_policy.py:416-426,611-613, frontend/components/cicd/CbomGatePolicyPage.tsx:223 — required for finding_code
  "cbom.gate.exc.code": {
    what: "For the Blocked finding code rule: the one finding code the exception covers. Other codes on the same finding still fail the build.",
    why: "A hard-coded key waiver never hides a static IV found next to it.",
    example: "HARDCODED_KEY.",
  },
  // src: backend/utilities/cicd/gate_policy.py:381-388,429-435, frontend/components/cicd/CbomGatePolicyPage.tsx:224 — bounded glob, required
  "cbom.gate.exc.location": {
    what: "Required: a glob on the finding's file path with at least one folder or file name without wildcards (* matches any characters, including /). A glob that matches everything, such as * or **, is refused.",
    why: "Limits the waiver to the vendor or legacy code that cannot change yet.",
    example: "vendor/hsm/*.",
  },
  // src: backend/utilities/cicd/gate_policy.py:438, frontend/components/cicd/CbomGatePolicyPage.tsx:225 — required, up to 300 characters
  "cbom.gate.exc.reason": {
    what: "Why the finding is accepted for now, up to 300 characters. Shown in every verdict that uses the exception.",
    why: "Auditors and developers see why a weak algorithm passed the gate.",
    example: "HSM firmware upgrade booked for January (CHG-4411).",
  },
  // src: backend/utilities/cicd/gate_policy.py:73,439-452, frontend/components/cicd/CbomGatePolicyPage.tsx:226 — at most 366 days ahead
  "cbom.gate.exc.expires": {
    what: "The last day the exception applies (inclusive), at most 366 days from today when saved. From the next day the finding fails the build again.",
    why: "Forces a review instead of a permanent hole in the gate.",
    example: "2027-01-31.",
  },
} as const satisfies TipAreaText;

export default TEXT;
