# AGENTS.md

Notes for agents and developers working on the LCW Admin API.

**`README.md` is the authority on what this service is** — its routes, how
authorization works, why the audit log is shaped the way it is, and what to
watch for when deploying. It also lists four `sam local` behaviours that will
cost you a day each. Read it first, and don't duplicate it here: this file
covers only how to get a working environment and what to run in it.

## What you need running

The admin API talks to **DynamoDB only** — no S3, no WAS, no login API. The
only AWS SDK client any handler imports is `@aws-sdk/client-dynamodb`; the rest
of their dependencies are the `@interop` signing and digest libraries. So the
admin loop is three processes, not the wallet's six:

| Process | Port | From |
| --- | --- | --- |
| DynamoDB Local | 8000 | the `docker run` below |
| the admin API (this repo) | 3002 | `sam local start-api` |
| the admin console | 5174 | `lcw-admin-front-end` |

You do **not** need `was-server-aws` or `lcw-back-end` to work on this repo:
`add-admin.mjs` creates the admin and audit tables, and `scripts/smoke.mjs`
creates the accounts table (`lcw-accounts`, keyed by email) when it is
missing. Start the one container:

```bash
docker network create lcw-local 2>/dev/null
docker run -d --name lcw-dynamodb --network lcw-local -p 8000:8000 \
  amazon/dynamodb-local:latest -jar DynamoDBLocal.jar -inMemory -sharedDb
```

`-sharedDb` is not optional. Without it DynamoDB Local namespaces tables per
access-key/region pair, and `add-admin.mjs` and the Lambdas end up looking at
two different namespaces — the table is created and the function still reports
`ResourceNotFoundException`.

## Bring it up

```bash
npm ci        # also installs src/authorizer's dependencies, see below
sam build

# register yourself as an admin; creates the local tables if missing
node scripts/add-admin.mjs --endpoint-url http://localhost:8000 \
  --email you@example.org --passphrase 'a long passphrase'

# the admin API, on :3002
sam local start-api --port 3002 --region us-east-1 \
  --docker-network lcw-local \
  --parameter-overrides DynamoEndpointUrl=http://lcw-dynamodb:8000 ExpectedHost=localhost:3002 \
  --warm-containers EAGER
```

Both parameter overrides are required and neither can be dropped:

- `DynamoEndpointUrl` is read by each function itself rather than being
  `AWS_ENDPOINT_URL_DYNAMODB`, because `sam local` renders an unset parameter as
  an empty string instead of omitting the variable, and an empty endpoint is not
  something the SDK ignores.
- `ExpectedHost` has no default **on purpose**, and an empty value disables host
  pinning entirely. It must match the host the console actually calls.

Then start the console from `lcw-admin-front-end` — see its `AGENTS.md`.

Port 3002 is only a convention: another local service may hold it (the PWS
reference server does). Any free port works as long as `ExpectedHost`, the
console's `VITE_ADMIN_API_BASE_URL` and `smoke.mjs --base` all name it.

## Tests

```bash
npm test                                         # 12 authorizer unit tests, in-process
node scripts/smoke.mjs --passphrase 'a long passphrase'   # the whole API, end to end
```

`npm test` is what CI gates on. The tests sign genuine invocations and assert
that a non-admin is refused, that a signature cannot be replayed against
another route or method, and that claiming a registered admin's `keyId` without
their key fails. They need no stack and no credentials.

`scripts/smoke.mjs` needs the API running. It seeds two throwaway accounts (one
that agreed to be contacted, one registered before the question), lists,
filters and reads them, deletes both, and checks the deletions were recorded
with the whole row, including the digest strip attack against `POST /login`.
It never touches accounts it did not create.

**`npm ci` at the root installs `src/authorizer`'s dependencies too**, through a
`postinstall` hook. It has to: the authorizer keeps its own `package.json` and
its tests import `aws-sdk-client-mock` from there, so a clean checkout that ran
only the root install used to fail `npm test` with
`ERR_MODULE_NOT_FOUND: Cannot find package 'aws-sdk-client-mock'`.

## CI

`.github/workflows/ci.yml` runs `npm ci` and `npm test` on every pull request,
whatever its base branch. It does not run `sam build` or `sam validate` — those
need the SAM CLI in the runner and would roughly triple the job, and the
authorizer's signature verification is the part worth gating on first. Adding
them is a reasonable next step.

Note that `sam validate` would not have caught the longhand IAM policies
described in `README.md`; checking those means expanding the template with
`samtranslator` and reading the roles.
