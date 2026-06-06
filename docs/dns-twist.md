# DNS Twist — look-alike / permutation methodology

Generate and resolve domain permutations to surface **typosquats, look-alikes, and impersonation
infrastructure** around a target. Use this to seed a focused, high-signal permutation set — not an
exhaustive brute force.

## Fuzzers (dnstwist)
- **homoglyph** — confusable characters (`paypal` → `paypaI`, `rn`↔`m`, `0`↔`o`, IDN/punycode).
- **typo / addition / omission / repetition / transposition / replacement** — keyboard-adjacent slips.
- **bitsquat** — single bit-flips (rare but real for high-traffic brands).
- **tld-swap** — same name on another TLD (`.com`→`.co`/`.net`/`.org`/ccTLD/`.app`/`.io`).
- **subdomain / hyphenation / combosquat** — `secure-paypal.com`, `paypal-login.com`, `paypal.support`.
- **dictionary / wordy** — brand + a service word (`paypal-billing`, `login-paypal`).

## Cloud default-naming patterns (high-value custom permutations)
Cloud resources tied to a brand often follow default naming — generate and check these as extra
permutations from the brand/company token (`acme`, `acmecorp`):
- **Azure**: `<name>.blob.core.windows.net`, `<name>.azurewebsites.net`, `<name>.azurestaticapps.net`,
  `<name>.azureedge.net`, `<name>.azure-api.net`, `<name>.database.windows.net`,
  `<name>.servicebus.windows.net`, `<name>.vault.azure.net`.
- **AWS**: `<name>.s3.amazonaws.com`, `<name>.s3.<region>.amazonaws.com`, `<name>.cloudfront.net`,
  `<name>.elasticbeanstalk.com`, `<name>.execute-api.<region>.amazonaws.com`, `<name>.amazonaws.com`.
- **GCP**: `<name>.storage.googleapis.com`, `<name>.appspot.com`, `<name>.cloudfunctions.net`,
  `<name>.run.app`, `<name>.web.app`, `<name>.firebaseapp.com`.
- Others: `<name>.herokuapp.com`, `<name>.netlify.app`, `<name>.vercel.app`, `<name>.pages.dev`,
  `<name>.github.io`, `<name>.zendesk.com`, `<name>.statuspage.io`, `<name>.atlassian.net`.

## Other clues to fold into the permutation set
- **Certificate transparency** — the target's existing subdomains (from `certificate_info`) reveal its
  naming conventions and service words; mirror those into permutations.
- **Brand tokens** — the registrable label without the TLD, plus the company short name.

## Triage (which hits matter)
A **registered/resolving** permutation is the positive signal. Then judge intent:
- **Malicious / phishing-suspected** — login/secure/verify/billing wording, recent registration, MX set
  (can receive mail), parked-then-active, or hosting unrelated to the brand.
- **Defensive / owned** — resolves to the brand's own infra/registrar (the company registered it to
  protect customers) — not a threat.
- **Unclear** — registered but inert/parked; note and watch.

Keep it focused: prefer a curated 10–40 high-signal permutations over thousands of low-value ones.
