#!/usr/bin/env node
// Exercises every admin route against a running API, signing each request as a
// registered admin. Intended for the local stack:
//
//   node scripts/smoke.mjs --passphrase 'admin-secret-seed-that-is-long-e'
//
// It seeds two throwaway wallet accounts directly in DynamoDB (one that agreed
// to be contacted, one registered before the question was asked), then lists,
// filters, reads and deletes them through the API. It never touches accounts
// it did not create, so it is safe to run alongside the wallet's own local
// stack.
import '@interop/http-client'
import { signCapabilityInvocation } from '@interop/http-signature-zcap-invoke'
import { createHeaderValue } from '@interop/http-digest-header'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { DynamoDBClient, PutItemCommand, GetItemCommand, CreateTableCommand } from '@aws-sdk/client-dynamodb'

const args = Object.fromEntries(
  process.argv.slice(2).reduce((pairs, arg, i, all) => {
    if (arg.startsWith('--')) pairs.push([arg.slice(2), all[i + 1]?.startsWith('--') === false ? all[i + 1] : true])
    return pairs
  }, [])
)

const BASE = (args.base ?? 'http://localhost:3002').replace(/\/+$/, '')
const ENDPOINT = args['endpoint-url'] ?? 'http://localhost:8000'
const ACCOUNT_TABLE = args['account-table'] ?? 'lcw-accounts'
const PASSPHRASE = args.passphrase ?? 'admin-secret-seed-that-is-long-e'
const AGREED_EMAIL = args.email ?? 'smoke-test@example.org'
const EARLIER_EMAIL = AGREED_EMAIL.replace('@', '+earlier@')

const dynamo = new DynamoDBClient({
  region: 'us-east-1',
  endpoint: ENDPOINT,
  credentials: { accessKeyId: 'localtest', secretAccessKey: 'localtest' }
})

async function keyFromPassphrase (passphrase) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(passphrase))
  const keyPair = await Ed25519VerificationKey.generate({ seed: new Uint8Array(digest) })
  keyPair.controller = `did:key:${keyPair.fingerprint()}`
  keyPair.id = `${keyPair.controller}#${keyPair.fingerprint()}`
  return keyPair
}

const adminKey = await keyFromPassphrase(PASSPHRASE)
// A second key, held by nobody the admin table knows about.
const strangerKey = await keyFromPassphrase('not-an-admin-passphrase-at-all!!')

async function call (method, path, { json, key = adminKey } = {}) {
  const url = `${BASE}${path}`
  const headers = await signCapabilityInvocation({
    url,
    method,
    headers: { host: new URL(url).host },
    ...(json ? { json } : {}),
    capabilityAction: method,
    invocationSigner: key.signer()
  })
  const response = await fetch(url, {
    method,
    headers: { ...headers, ...(json ? { 'content-type': 'application/json' } : {}) },
    ...(json ? { body: JSON.stringify(json) } : {})
  })
  const text = await response.text()
  let body
  try { body = JSON.parse(text) } catch { body = text }
  return { status: response.status, body }
}

// '@' and '+' are legal in a URL path segment, and both ends have to agree on
// the literal bytes because the signature covers the request target. Leaving
// them unencoded is what makes that agreement hold: API Gateway hands the
// authorizer the path exactly as sent, while sam local decodes it first, so an
// encoded '@' verifies deployed and fails locally. Anything genuinely unsafe
// is still encoded.
const pathSegment = (email) =>
  encodeURIComponent(email).replace(/%40/g, '@').replace(/%2B/gi, '+')

let failures = 0
function check (name, condition, detail) {
  console.log(`${condition ? '  ok  ' : 'FAIL  '}${name}`)
  if (!condition) {
    failures++
    if (detail !== undefined) console.log(`        ${JSON.stringify(detail)}`)
  }
}

console.log(`Admin DID: ${adminKey.controller}`)
console.log(`Against:   ${BASE}\n`)

// The accounts table is lcw-back-end's; against DynamoDB Local alone it does
// not exist yet, so it is created here in its shape (keyed by email).
try {
  await dynamo.send(new CreateTableCommand({
    TableName: ACCOUNT_TABLE,
    AttributeDefinitions: [{ AttributeName: 'email', AttributeType: 'S' }],
    KeySchema: [{ AttributeName: 'email', KeyType: 'HASH' }],
    BillingMode: 'PAY_PER_REQUEST'
  }))
  console.log(`Created the local ${ACCOUNT_TABLE} table`)
} catch (error) {
  if (error.name !== 'ResourceInUseException') throw error
}

// Seeded directly, in the shape lcw-back-end writes: creating wallet accounts
// is not something the admin API can do, by design.
const agreedAt = new Date().toISOString()
for (const item of [
  {
    email: { S: AGREED_EMAIL },
    did: { S: strangerKey.controller },
    token: { S: 'smoke-registration-code' },
    confirmationKey: { S: 'none' },
    CreatedAt: { S: agreedAt },
    contactOptIn: { BOOL: true },
    contactOptInUpdatedAt: { S: agreedAt }
  },
  {
    email: { S: EARLIER_EMAIL },
    did: { S: strangerKey.controller },
    token: { S: 'smoke-registration-code' },
    CreatedAt: { S: agreedAt }
  }
]) {
  await dynamo.send(new PutItemCommand({ TableName: ACCOUNT_TABLE, Item: item }))
}
console.log(`Seeded ${AGREED_EMAIL} and ${EARLIER_EMAIL}\n`)

// A body, even an empty one: the authorizer requires body-carrying methods to
// sign a digest, so an unsigned-body POST is refused by design.
const login = await call('POST', '/login', { json: {} })
check('POST /login identifies the admin', login.status === 200 && login.body.did === adminKey.controller, login)

// Signed for the same target but with no body, then replayed with one. The
// signature cannot cover a digest it never had, so the authorizer refuses it
// before any handler sees it.
const stripped = await (async () => {
  const url = `${BASE}/login`
  const headers = await signCapabilityInvocation({
    url,
    method: 'POST',
    headers: { host: new URL(url).host },
    capabilityAction: 'POST',
    invocationSigner: adminKey.signer()
  })
  const body = JSON.stringify({ injected: true })
  const digest = await createHeaderValue({ data: new TextEncoder().encode(body) })
  const response = await fetch(url, { method: 'POST', headers: { ...headers, digest, 'content-type': 'application/json' }, body })
  return response.status
})()
check('a body added to a signature that never covered one is refused', stripped === 403, stripped)

const stranger = await call('GET', '/accounts', { key: strangerKey })
check('a non-admin is refused', stranger.status === 403, stranger)

// 401, not 403: with no Authorization header there is no identity source, so
// the gateway refuses before the authorizer is ever invoked.
const unsigned = await fetch(`${BASE}/accounts`)
check('an unsigned request is refused', unsigned.status === 401, unsigned.status)

const list = await call('GET', '/accounts')
check('GET /accounts lists accounts', list.status === 200 && Array.isArray(list.body.accounts), list)
check('the seeded accounts are listed', [AGREED_EMAIL, EARLIER_EMAIL].every(email =>
  (list.body.accounts ?? []).some(a => a.email === email)), list.body)

const search = await call('GET', '/accounts?q=smoke-test')
check('GET /accounts?q= filters', search.status === 200 && (search.body.accounts ?? []).every(a =>
  `${a.email}${a.did}`.includes('smoke-test')), search)

const listed = (email) => (search.body.accounts ?? []).find(a => a.email === email)
check('the list carries each account\'s contact choice', listed(AGREED_EMAIL)?.contactOptIn === true &&
  listed(AGREED_EMAIL)?.contactOptInUpdatedAt === agreedAt &&
  listed(EARLIER_EMAIL)?.contactOptIn === false && listed(EARLIER_EMAIL)?.contactOptInUpdatedAt === undefined,
  search.body.accounts)

const got = await call('GET', `/accounts/${pathSegment(AGREED_EMAIL)}`)
check('GET /accounts/{email} reads one account, with its contact choice', got.status === 200 &&
  got.body.account?.did === strangerKey.controller && got.body.account?.contactOptIn === true, got)

const earlier = await call('GET', `/accounts/${pathSegment(EARLIER_EMAIL)}`)
check('an account registered before the question reads as not agreed', earlier.status === 200 &&
  earlier.body.account?.contactOptIn === false && earlier.body.account?.contactOptInUpdatedAt === undefined, earlier)

const deletedEarlier = await call('DELETE', `/accounts/${pathSegment(EARLIER_EMAIL)}`)
check('DELETE /accounts/{email} removes the row', deletedEarlier.status === 200 && deletedEarlier.body.deleted?.email === EARLIER_EMAIL, deletedEarlier)

const deleted = await call('DELETE', `/accounts/${pathSegment(AGREED_EMAIL)}`)
check('a second deletion', deleted.status === 200 && deleted.body.deleted?.email === AGREED_EMAIL, deleted)

const afterDelete = await dynamo.send(new GetItemCommand({
  TableName: ACCOUNT_TABLE, Key: { email: { S: AGREED_EMAIL } }
}))
check('the row is gone', afterDelete.Item === undefined, afterDelete.Item)

const gone = await call('GET', `/accounts/${pathSegment(AGREED_EMAIL)}`)
check('a deleted account still has its history, holding the whole row', gone.status === 404 && (gone.body.history ?? []).some(
  h => h.action === 'account.delete' && h.detail?.removed?.item?.token?.S === 'smoke-registration-code' &&
       h.detail?.removed?.item?.contactOptIn?.BOOL === true), gone.body)

const audit = await call('GET', '/audit')
check('GET /audit lists both deletions newest first', audit.status === 200 &&
  audit.body.entries?.[0]?.action === 'account.delete' && audit.body.entries?.[0]?.targetEmail === AGREED_EMAIL &&
  audit.body.entries?.[1]?.action === 'account.delete' && audit.body.entries?.[1]?.targetEmail === EARLIER_EMAIL,
  audit.body.entries?.slice(0, 2))

// Paged through the time-ordered index, so "newest first" holds across pages
// rather than only within one.
const firstPage = await call('GET', '/audit?limit=1')
check('GET /audit pages, newest first', firstPage.status === 200 &&
  firstPage.body.entries?.length === 1 &&
  firstPage.body.entries[0].targetEmail === AGREED_EMAIL &&
  Boolean(firstPage.body.nextCursor), firstPage.body)

const secondPage = await call('GET', `/audit?limit=1&cursor=${encodeURIComponent(firstPage.body.nextCursor ?? '')}`)
check('the next page continues where the first left off', secondPage.status === 200 &&
  secondPage.body.entries?.[0]?.targetEmail === EARLIER_EMAIL, secondPage.body.entries)

console.log(failures === 0 ? '\nAll checks passed.' : `\n${failures} check(s) failed.`)
process.exit(failures === 0 ? 0 : 1)
