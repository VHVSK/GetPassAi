# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Use GitHub's **private vulnerability reporting**: on the repository page, go to **Security → Report a vulnerability**. Your report stays private until it is fixed. No email address is needed.

If private vulnerability reporting is not available for some reason, open an issue titled "Security report — please contact me" with no details, and the maintainer will get in touch.

## What to include

- What the problem is, in plain words.
- Steps to reproduce it (a minimal example is ideal).
- What you think the impact is: what an attacker could do with it.
- Your GitHub username, if you want to be thanked in the changelog.

## What happens next

- The maintainer will confirm receipt and assess the report. GetPassAi is a side project by a single maintainer, so please expect a **best-effort** response time — normally within a few days, sometimes longer. There is no paid support team.
- If the report is valid, the issue will be fixed, the fix will be released, and the reporter will be credited (unless they prefer to stay anonymous).
- Please give the maintainer a reasonable time to fix the issue before disclosing it publicly — **90 days** is the standard window.

## Scope

**In scope:**
- The vault code in this repository (PHP, JavaScript, SQL schema).
- Authentication and session handling, encryption, access control between users.
- Security headers and hosting configuration as documented.

**Out of scope:**
- The live hosting account or DNS (report those to the hosting provider / registrar).
- Social engineering, phishing, or physical access to a user's device.
- Reports that require a user to install malware or a malicious browser extension first.
- Automated scanner output without a demonstrated impact.
- Denial-of-service by flooding the free service (rate limits exist, but a small free service cannot absorb a large attack — that is expected, not a vulnerability).

## Known limits (not vulnerabilities)

These are documented limitations, not surprises — please do not report them as vulnerabilities:

- The server currently sees the site password at sign-in (SRP is planned; see the security plan in this repo).
- There is no account recovery yet — a forgotten site password means a lost vault.
- The service has not been independently audited yet.
