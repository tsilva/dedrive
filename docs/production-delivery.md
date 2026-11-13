# Production delivery

A successful `CI` completion for a push to `main` triggers `.github/workflows/production-delivery.yml` through `workflow_run`. It tests delivery boundaries and rechecks the same commit’s already successful CI before retrieving secrets. Then it syncs the fixed production allowlist in `.github/scripts/production-delivery.json`, builds that exact commit on GitHub Actions, stages the prebuilt Vercel deployment, and verifies it before promotion. Vercel’s automatic Git deployments are disabled so they cannot race the sync.

Automatic delivery accepts only successful main-push CI from this repository,
for the same SHA as the delivery run and the current head of `main`. The CI
workflow path, immutable repository IDs, run ID and rerun attempt are checked
again against GitHub before secret access. Failed, cancelled, forked, stale or
superseded runs cannot deploy. Manual and secret-change relay dispatches remain
available, but fail immediately if the latest exact-commit CI is not already
successful. CI artifacts and caches are not imported into the trusted sync job.

This app has no private production application keys; its empty secret-sync allowlist requires no vault identity. The provider credential is a project-scoped `VERCEL_TOKEN` stored in the repository’s GitHub Production environment. No general CLI login is copied into GitHub.

The workflow does not run on pull requests or forks, export `.env` files, upload secret artifacts, delete secret variables, or change preview/development variables. All required source keys and destination targets are checked before writes. Failed CI or sync prevents deployment. Existing production remains live on failure.

After changing a production secret, use **Actions → Production delivery → Run workflow → main** to sync and deploy. A secret change alone does not trigger delivery. There is no schedule or automatic retry; rerun a failed workflow manually after fixing the cause. For an old failed commit superseded by a newer main commit, run a fresh workflow on main. Deployment tokens expire after one year and need rotation before expiry.



Production delivery classifies public settings through the pinned `configNames` list; all other allowlisted values remain write-only Secrets. Vercel’s Require Separate Values policy stays enabled: real Production secrets must differ from non-production values. Existing variables are updated by their exact Production IDs. A legacy Secret explicitly listed as public configuration is replaced only in Production because Vercel cannot convert it to Config in place; Preview and Development rows are preserved. Provider responses and credential values are never logged. A failed sync holds deployment; rerun delivery after fixing the named key at its source.

## Staging a prebuilt deployment

Use **Actions → Production delivery → Run workflow → main** with **stage_prebuilt** selected to build and verify a Vercel deployment while production domains keep serving the live release. Leave the option clear for a production delivery.
