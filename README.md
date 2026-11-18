# LCW Admin API

> [!IMPORTANT]
> **Alpha.** This is part of the Learner Credential Wallet alpha, an early test
> version. It may change without notice. We read issues, but may not answer or
> fix them during the alpha.

Administration of **Learner Credential Wallet accounts**: viewing them,
searching them, listing who agreed to be contacted, and deleting them. An
HTTP API of AWS Lambda functions behind a zcap-signature authorizer, deployed
with AWS SAM. The console that drives it is
[lcw-admin-front-end](https://github.com/digitalcredentials/lcw-admin-front-end).

This is deliberately a small, separate thing. It is not part of the wallet, it
is not a general back office, and it is not where credentials live.

## What it is not

The wallet is three repos - [lcw-front-end][fe], [lcw-back-end][be] and
[was-server-aws][was] - and this is a fourth that shares exactly one thing with
them: **the accounts table** (`lcw-accounts`). That table holds an email, the
`did:webvh` the account registered, the registration token sign-in hands
back, timestamps, and the tester's answer to "Contact me with news and
updates" (`contactOptIn`, `contactOptInUpdatedAt`; a row without them, an
account registered before the question, reads as not agreed). That is the
whole of what can be administered here.

Credentials are not in it. They live, encrypted, in the account's storage
Space on the PWS server, which this API holds **no permission of any kind
over** - no S3 policy, not even read - and which stays controlled by the
account's own keys. An admin can stop an account signing in. An admin cannot
open its storage, copy it, or destroy it.

[fe]: https://github.com/digitalcredentials/lcw-front-end
[be]: https://github.com/digitalcredentials/lcw-back-end
[was]: https://github.com/digitalcredentials/was-server-aws

## The shape of it

| Method | Path | What it does |
| --- | --- | --- |
| POST | `/login` | Reports which admin the caller proved they are |
| GET | `/accounts` | One page of accounts; `?q=` searches email and DID, `?limit=` sizes the page (at most 200), `?cursor=` continues |
| GET | `/accounts/{email}` | One account, with everything admins have done to it |
| DELETE | `/accounts/{email}` | Removes the account row, recording it first |
| GET | `/audit` | Recorded admin actions, newest first; `?limit=` and `?cursor=` page |

Three tables are involved. `lcw-accounts` (the accounts) is **owned by the
lcw-back-end stack**; this stack references it by name through the
`AccountTableName` parameter and never declares it, because two stacks
declaring one table would contend over it. `lcw-admin` and `lcw-admin-audit`
are declared here.

## How authorization works

Every request - `/login` included - is an individually signed zcap invocation,
verified by one Lambda authorizer before any handler runs. There is no session,
no token, no cookie: nothing is issued at login that could later be stolen or
replayed, and there is no server-side session state to compromise. A signature
authorizes one request, which is why the authorizer's result cache is disabled
(`ReauthorizeEvery: 0`).

The caller's identity comes from the `keyId` in their own signature, never from
anything they assert in a body or header. That DID is looked up in the admin
table, and verification then proves they hold its private key. The two failure
modes therefore are: not registered, or cannot sign. Both come back as a bare
403.

**Admins are their own table.** An admin is not a wallet account with a flag
set - `lcw-accounts` has no column this API consults for privilege - so no
wallet account can be escalated into an admin, by this API or by anything that
writes to that table.

**There is no way to become an admin through this API.** Membership is granted
out of band with [`scripts/add-admin.mjs`](scripts/add-admin.mjs), by whoever
operates the deployment. An admin API that can grow its own membership is a
different and much larger thing than this one.

**There is no way to create a wallet account through this API either.**
Registration stays user-initiated, through the email confirmation flow in
lcw-back-end.

**The host is pinned, always.** The signed request target is built from the
caller's own `Host` header, so on its own the host check compares that header to
itself and binds a signature to nothing in particular. `ExpectedHost` fixes it
to this deployment, so an invocation made against a staging API cannot be
replayed against a production one.

It has **no default**, deliberately: an empty value disables the check, and a
parameter that can be omitted is one that eventually will be - a deploy
accepting defaults would ship with the pinning silently off. Locally, pass
`ExpectedHost=localhost:3002`; it must match the host the console actually calls,
letter case aside.

**A request body has to be authenticated in two places.** An HTTP API
authorizer event carries headers but no body, so verifying the signature proves
the signed `Digest` header is genuine while proving nothing about the bytes that
actually arrived. No handler acts on a body today, but one that does must
re-check it against that digest and refuse a mismatch.

That is only worth anything if the digest was signed, and by default it is not
always required to be. `@interop/http-signature-zcap-verify` adds `digest` to
the headers a signature must cover **only when the request carries a
`Content-Type`** - and the caller chooses whether to send one. So the authorizer
requires `digest` explicitly for every body-carrying method (`POST`, `PUT`,
`PATCH`). Without that, a signature made over a bodyless request to the same
target could be replayed with any body and a matching attacker-computed digest,
and a handler's own comparison would succeed against the attacker's number.

The authorizer refuses a body-carrying signature that does not cover a digest,
and `scripts/smoke.mjs` runs that strip attack against the running API's
`POST /login`.

## Every action is recorded

`lcw-admin-audit` is append-only to this API. Every function that writes to it
is granted `dynamodb:PutItem` on that table and nothing else, and each write is
conditional on its key not already existing, so a record can neither be altered
nor silently overwritten through the API. (`DynamoDBWritePolicy` would have
granted `UpdateItem` as well, which is why the policies here are written out
longhand. `sam validate` will not tell you that; expanding the template with
`samtranslator` and reading the roles will.)

What that does **not** cover: whoever holds AWS credentials for the table can
edit or delete rows directly, and `scripts/add-admin.mjs` writes to it as that
principal. The guarantee is against the API being turned against its own log,
not against the account that owns the table.

Every writer goes through one recorder ([`src/shared/audit.mjs`](src/shared/audit.mjs)),
so the `log` partition value the global feed depends on exists in a single
place. A writer that omitted it would keep working - the record would land, and
show under the account - while vanishing from `GET /audit`. The recorder is also
retry-safe: a `PutItem` whose response is lost is retried by the SDK, and that
retry fails its own condition, which taken for a collision would append a second
copy of one action to a log that cannot be corrected.

Each record names the admin who acted (DID and email), what they did, to whom,
and when. Nothing destructive proceeds without an identity to attribute it to:
if the authorizer context is missing, the handler refuses rather than writing an
anonymous record.

The record is written **before** the account is touched, and it carries enough
to undo the action: a deletion stores the row that was removed exactly as it
was stored (`detail.removed.item`, every attribute lcw-back-end keeps on it,
the registration token and the contact choice included), so putting it back
restores the account's sign-in intact.

Two consequences follow, both intended. A failure to record aborts the action
rather than performing it unrecorded. And an action that is recorded but then
fails would leave a record of something that did not happen - so the handler
appends a second record saying so (`account.delete.aborted`). The log is only
ever added to, so a correction is another entry, never an edit.

The write itself is conditional on what was read: a deletion only applies if
the account still holds the DID the record names. A deletion racing another
change returns 409 rather than removing a row the log does not describe -
which would have made the recorded undo restore the wrong one.

Granting and revoking admin rights is recorded too, by `add-admin.mjs`, marked
as unauthenticated because it is - that script is run by whoever holds AWS
credentials, and nothing about it is signed. Without those entries, an audit row
naming a DID could not be tied to a person once that admin was removed.

## There is no DID reset

An earlier version could replace the DID on an account's row, which handed the
account over when the storage server read its controller from this table. It
no longer does: an account is a `did:webvh` that controls its own storage
Space, and the row's DID only decides who passes lcw-back-end's sign-in check.
Replacing it would lock the tester out of the wallet and let the new key's
holder pass that check without reaching the account's data, so the route is
gone. A tester who loses their password recovers through the wallet's own
recovery codes.

## Who agreed to be contacted

The register page asks "Contact me with news and updates", unticked by
default, and testers change their answer in the wallet's Settings; lcw-back-end
keeps it on the account row. `GET /accounts` returns it on every account
(`contactOptIn`, and `contactOptInUpdatedAt` for when). The console loads every
account, filters and searches them in the browser, and exports the filtered
rows as a CSV, so "who agreed to be contacted" is its Contact column set to
Agreed.

## Running it locally

DynamoDB Local stands in for the real tables, so nothing here needs AWS
credentials. Start it as `AGENTS.md` shows, then:

```bash
npm ci                           # scripts and tests, authorizer deps included
sam build

# register yourself as an admin (creates the local tables if missing)
node scripts/add-admin.mjs --endpoint-url http://localhost:8000 \
  --email you@example.org --passphrase 'a long passphrase'

# the admin API, on :3002 (any free port, as long as ExpectedHost names it)
sam local start-api --port 3002 --region us-east-1 \
  --docker-network lcw-local \
  --parameter-overrides DynamoEndpointUrl=http://lcw-dynamodb:8000 ExpectedHost=localhost:3002 \
  --warm-containers EAGER
```

The script refuses to register a DID that already belongs to another admin: two
admins sharing one key would make every action signed by it ambiguous, and the
authorizer refuses such a DID outright rather than attributing an action to
whichever row an index returned first. (The check reads a GSI, which cannot be
read consistently, so two registrations racing each other could still both land
- the authorizer then refuses that DID until one row is removed.)

Re-running it with the same DID does nothing and records nothing: the log is a
record of changes, not of invocations. A grant or revocation is recorded
**before** it is applied, as in the API, and a missing audit table aborts the
change rather than proceeding unrecorded.

`--passphrase` derives the DID exactly as the console's sign-in does
(`SHA-256(passphrase)` as the Ed25519 seed); an admin's key has nothing to do
with any wallet account's. Prefer `--did` outside local development, so the
passphrase never leaves the admin's machine.

Then exercise the whole API end to end:

```bash
node scripts/smoke.mjs --passphrase 'a long passphrase'   # --base http://localhost:PORT for another port
```

It creates the local `lcw-accounts` table if it is missing, seeds two
throwaway accounts of its own (one that agreed to be contacted, one registered
before the question), lists, filters and reads them, deletes both, and checks
that the deletions were recorded with the whole row. It never touches accounts
it did not create.

## Tests

```bash
npm test        # authorizer, in-process, against real signed invocations
```

These are the tests that matter most here: they sign genuine invocations and
assert that a non-admin is refused, that a signature cannot be replayed against
another route or another method, and that claiming a registered admin's `keyId`
without their key does not work.

## Four things that will bite you

**1. `sam local` decodes the request path; API Gateway does not.** The
signature covers the request target byte for byte, so an email encoded as
`smoke-test%40example.org` verifies when deployed and fails locally. Leave `@`
and `+` unencoded in the path - both are legal there - and the two agree. See
`pathSegment` in `scripts/smoke.mjs`.

**2. The query string is part of the signed target.** The authorizer
reassembles it from `rawQueryString`, which `sam local` does not provide, and
falls back to rebuilding it from `queryStringParameters`.

**3. `AWS_ENDPOINT_URL_DYNAMODB` cannot come from a template parameter.**
`sam local` renders an unset parameter as an empty string rather than omitting
the variable, and an empty endpoint is not something the SDK ignores. Hence
`DYNAMO_ENDPOINT_URL`, which each function reads itself and applies only when
non-empty - the same shape as `AWS_ENDPOINT_URL_S3` in was-server-aws.

**4. The authorizer bundle needs a `createRequire` banner.** `undici`, pulled
in transitively by the document loader, `require()`s node builtins from inside
a CJS module, and esbuild's ESM output has no `require`. Without the banner in
`template.yaml` the function dies on cold start with *"Dynamic require of
node:assert is not supported"*. (was-server-aws has the same exposure and has
so far only been saved by an older resolved `undici`.)

## Deploying

Not to be done casually: the accounts table is shared with a live sandbox. The
sandbox serves this API at `admin-api.lcw-sandbox.org` and the console at
`admin.lcw-sandbox.org`:

```bash
sam build
sam deploy --stack-name lcw-admin-api --resolve-s3 --capabilities CAPABILITY_IAM \
  --parameter-overrides AccountTableName=lcw-accounts \
    ApiDomainName=admin-api.lcw-sandbox.org HostedZoneId=Z04250862QG6MQUAE24XV \
    ExpectedHost=admin-api.lcw-sandbox.org
```

- `AccountTableName` defaults to `lcw-accounts`, lcw-back-end's table; name it
  explicitly anyway, since it is the one table here that is not this stack's.
- `ApiDomainName` and `HostedZoneId` make the stack create the custom domain,
  its certificate (validated through the zone) and the alias record, so the
  host is known before the first deploy. `ExpectedHost` has no default and must
  name the same host.
- Register the first admin with `add-admin.mjs` against the deployed
  `lcw-admin` table (no `--endpoint-url`, AWS credentials for the account, and
  `--did` rather than `--passphrase`); the console cannot be used at all until
  one exists.
- Both tables this stack declares keep `DeletionPolicy: Retain` and
  `UpdateReplacePolicy: Retain` with point-in-time recovery, so deleting the
  stack or renaming a table parameter leaves the admin list and the audit log
  in place rather than deleting them; a replaced table has to be imported or
  restored by hand.
- `recent-index` is sparse on the `log` attribute, which every record written by
  this code carries. If a deployment ever predates that attribute, its older
  records will be missing from `GET /audit` (though still visible under the
  account) until they are backfilled.

## License

MIT. See [LICENSE](LICENSE).
