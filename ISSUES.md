# Deployment Hardening Issues

## Production Docker build review
Review the production Docker build for backend and frontend images, focusing on image size, cache usage, non-root execution, and removal of development-only dependencies. Confirm the final images are suitable for a public demo or staging environment.

## Nginx reverse proxy profile
Add a documented Nginx reverse proxy profile for the stack. It should cover request routing, static asset delivery, upstream health expectations, and the minimum config needed to run behind a public endpoint.

## TLS termination guide
Write a deployment guide for terminating TLS in front of the app. Include certificate handling, proxy headers, secure redirects, and the settings required on the app side to avoid mixed-content or cookie issues.

## Hardened secrets handling
Replace the current plain environment example with a hardened secrets workflow. Document which values must never be committed, how local overrides are loaded, and how production credentials should be injected.

## GitHub Actions CI pipeline hardening
Finish the CI hardening work by making the backend and frontend validation steps blocking, and document the exact validation commands used in CI. Include any remaining guardrails needed for production readiness.
