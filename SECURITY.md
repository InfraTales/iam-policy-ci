# Security policy

## Reporting a problem

Please don't report security problems in public GitHub issues. Use GitHub's private vulnerability reporting on this repository (Security tab, then "Report a vulnerability").

It helps to include the file and line or the commit, the steps to reproduce, and what an attacker could do with it.

## How this repo protects itself

[docs/security.md](docs/security.md) has the details and the reasons. In short:

- On every pull request, CI compares each role's access with a reviewed reference policy.
- No role may hold actions that escalate access, such as `iam:PassRole`, whatever its reference says.
- CI checks bucket and trust policies for public access.
- The CI role can only call four read-only Access Analyzer actions, and only workflows on `main` or in pull requests of this repository can assume it.
