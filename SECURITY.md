# Security Policy

## Authorized-use requirement

CyberSec AI Ecosystem is intended for defensive security, vulnerability management, incident response, controlled research and explicitly authorized security testing. Operators are responsible for defining and enforcing legal scope before scanning or executing response actions.

## Safety controls

- Discovery is fail-closed against configured authorized CIDRs.
- Explicit exclusions override authorized scopes.
- Selected critical actions require Human-in-the-Loop approval.
- Vulnerability remediation automation is recommendation-only in the current release.
- External vulnerability intelligence lookups can be disabled when asset fingerprints must remain inside the environment.

## Secrets

Never commit `.env`, API keys, private keys, certificates containing private material, production tokens, incident evidence or customer asset inventories.

## Reporting vulnerabilities

Use a private security channel for vulnerability reports. Do not open a public issue containing credentials, exploit material against production targets, customer data or sensitive evidence.
