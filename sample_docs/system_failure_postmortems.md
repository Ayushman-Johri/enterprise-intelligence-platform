# Platform Reliability Post-Mortems - FY2026 H1

## INC-1042: Payments API outage (Jan 14)
Duration: 2h 10m. Root cause: database connection pool exhaustion. The payments service opened a new
connection per request after a config change set `pool_size=0`. Under peak load the PostgreSQL
max_connections limit (500) was hit and requests timed out.
Fix: restored pool_size to 50, added a CI check that rejects pool_size below 10.

## INC-1077: Order service crash loop (Feb 3)
Duration: 45m. Root cause: memory leak in the PDF invoice renderer; pods were OOMKilled every 20 minutes.
Fix: upgraded the renderer library to v3.2 and set memory limit alerts at 80%.

## INC-1103: Login failures (Mar 9)
Duration: 1h 30m. Root cause: expired TLS certificate on the identity provider load balancer.
Certificate renewal was manual and the reminder email went to a former employee.
Fix: moved to automated certificate renewal (ACME) and added expiry monitoring 30 days before expiry.

## INC-1150: Search latency spike (Apr 21)
Duration: 3h. Root cause: database connection pool exhaustion in the search indexer caused by
long-running analytics queries holding connections. p95 latency rose from 300ms to 9s.
Fix: separate read replica for analytics, statement_timeout of 30s.

## INC-1188: Deployment rollback (May 30)
Duration: 25m. Root cause: configuration drift - production had a feature flag value that staging did not.
Fix: configuration is now managed in Git (GitOps) and diffed before each release.

## Summary of most common failure causes
1. Database connection pool exhaustion (2 incidents: INC-1042, INC-1150)
2. Configuration errors / drift (INC-1042 config change, INC-1188)
3. Certificate expiry (INC-1103)
4. Memory leaks (INC-1077)
