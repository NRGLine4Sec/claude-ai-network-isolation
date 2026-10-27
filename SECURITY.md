# Scope and security posture

## Nature of this repository

This repository is a **defensive characterization** effort. It documents, through
measurement, the observable behavior of the network containment of claude.ai's
code-execution environment, and derives a reusable design pattern for building
isolated environments.

It contains **no active operational exploit** against Anthropic's production
infrastructure. The probes provided (`probes/`) measure boundaries; they do not
cross them.

## What the probes do, and do not do

- **They do**: measure which ports egress, and the DNS, ICMP, and TLS behavior,
  and which tunneling protocols are blocked. The targets of active tests are
  benign public hosts (public DNS resolvers, test servers such as
  `scanme.nmap.org`, HTTP echo services), or reserved IPs (RFC 5737 / RFC 1918).
- **They do not**: cross the boundary to reach a blocked host, exfiltrate data,
  or attempt any sandbox escape.

Each probe carries a header explicitly stating "characterization, benign target".

## Third-party vulnerabilities cited

The document `docs/03-public-vulnerabilities.md` reviews vulnerabilities found by
other researchers. **All of them were responsibly disclosed and fixed by
Anthropic** before their respective authors published. This repository only
summarizes and sources them; it provides no exploit code.

## Accuracy caveats

- The attribution of the implementation to Google Cloud Secure Web Proxy is a
  **strong-inference deduction**, not a confirmation by Anthropic.
- The measurements describe **one** environment, at **one** date, observed from
  the inside. They may not generalize and may become outdated.

## Reporting

If you believe this repository accidentally contains anything that goes beyond
defensive characterization, open an issue or contact the maintainer, and the
item will be reviewed and removed if necessary.

To report a vulnerability to Anthropic directly, use their disclosure program:
https://hackerone.com/anthropic
