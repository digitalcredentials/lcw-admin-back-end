import { appendRecord } from '../shared/audit.mjs'
import {
  DynamoDBClient,
  GetItemCommand,
  DeleteItemCommand
} from '@aws-sdk/client-dynamodb'

// Overridden only for local development, where DYNAMO_ENDPOINT_URL points at
// a DynamoDB substitute; empty in every deployed environment.
const dynamoClient = new DynamoDBClient(
  process.env.DYNAMO_ENDPOINT_URL ? { endpoint: process.env.DYNAMO_ENDPOINT_URL } : {}
)
const ACCOUNT_TABLE_NAME = process.env.ACCOUNT_TABLE_NAME ?? 'lcw-accounts'
const AUDIT_TABLE_NAME = process.env.AUDIT_TABLE_NAME ?? 'lcw-admin-audit'


const json = (statusCode, body) => ({
  statusCode,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body)
})

const pathEmail = (event) => {
  const raw = event.pathParameters?.email ?? ''
  try {
    return decodeURIComponent(raw)
  } catch {
    return raw
  }
}

export const handler = async (event) => {
  const context = event.requestContext?.authorizer?.lambda ?? {}
  const admin = {
    adminDid: String(context.adminDid ?? ''),
    adminEmail: String(context.adminEmail ?? '')
  }
  // Nothing destructive happens unattributed. An empty identity means the
  // authorizer context did not arrive, which is a misconfiguration, not a
  // request to be honoured with an anonymous audit record.
  if (!admin.adminDid) {
    console.error('Refusing a deletion: the request carries no admin identity')
    return json(500, { error: 'Could not establish who is making this request.' })
  }

  const email = pathEmail(event)
  if (!email) {
    return json(400, { error: 'Missing email in path.' })
  }

  let account
  try {
    ({ Item: account } = await dynamoClient.send(new GetItemCommand({
      TableName: ACCOUNT_TABLE_NAME,
      Key: { email: { S: email } },
      // The row read here is what gets recorded as the means of restoring the
      // account, so it must be the row as it actually is. A stale replica
      // would have this record - and any restore from it - name a DID the
      // account no longer had.
      ConsistentRead: true
    })))
  } catch (error) {
    console.error('Error reading account before delete:', error)
    return json(500, { error: 'Failed to read account.' })
  }

  if (!account) {
    return json(404, { error: 'No such account.' })
  }

  // What an admin reads, and the row exactly as stored: `item` is what a
  // restore puts back, every attribute lcw-back-end keeps on it included
  // (the registration token sign-in returns, the contact choice).
  const removed = {
    email: account.email?.S,
    did: account.did?.S,
    createdAt: account.CreatedAt?.S,
    item: account
  }

  // Recorded before the row is removed, and the record carries the whole row.
  // Two consequences, both deliberate: an audit failure aborts the deletion
  // rather than losing the trace of it, and the record is everything needed to
  // put the account back. The cost is that a delete which then fails leaves a
  // record of an action that did not complete - the response says so, and the
  // row is still there to prove it.
  let recordedAt
  try {
    recordedAt = await appendRecord(dynamoClient, AUDIT_TABLE_NAME, {
      targetEmail: email,
      action: 'account.delete',
      admin,
      detail: { removed }
    })
  } catch (error) {
    console.error('Error recording deletion:', error)
    return json(500, { error: 'Failed to record the action; nothing was deleted.' })
  }

  try {
    await dynamoClient.send(new DeleteItemCommand({
      TableName: ACCOUNT_TABLE_NAME,
      Key: { email: { S: email } },
      // Conditional on the row that was read and recorded, not merely on one
      // existing: deleting a row that changed in between would record a
      // restore payload that no longer matches what was removed.
      ConditionExpression: removed.did === undefined
        ? 'attribute_exists(email) AND attribute_not_exists(#did)'
        : 'attribute_exists(email) AND #did = :did',
      ExpressionAttributeNames: { '#did': 'did' },
      ...(removed.did === undefined
        ? {}
        : { ExpressionAttributeValues: { ':did': { S: removed.did } } })
    }))
  } catch (error) {
    const raced = error.name === 'ConditionalCheckFailedException'
    console.error('Error deleting account:', error)
    // The record above says this deletion happened. It did not, so say so in
    // the log as well as in the response - the log cannot be edited, only
    // added to.
    try {
      await appendRecord(dynamoClient, AUDIT_TABLE_NAME, {
        targetEmail: email,
        action: 'account.delete.aborted',
        admin,
        detail: {
          // Names the record it retracts, so a reader of an append-only log
          // can pair the two even when several actions land together.
          corrects: recordedAt,
          removed,
          why: raced
            ? 'The account changed or was already gone when the deletion was applied; nothing was changed.'
            : 'The write failed; nothing was changed.'
        }
      })
    } catch (recordError) {
      console.error('Error recording the aborted deletion:', recordError)
    }
    return json(raced ? 409 : 500, {
      error: raced
        ? 'This account changed or was already deleted. Nothing was changed; reload and try again.'
        : 'Failed to delete the account.'
    })
  }

  // The account's storage Space is untouched: this API holds no permission
  // over it, and it stays controlled by the account's own DID. What the
  // removal ends is signing in: lcw-login answers only an email this table
  // holds, so the wallet cannot finish a sign-in until the row is put back.
  return json(200, {
    deleted: removed,
    note: 'The account row was removed, so this account can no longer sign in to the wallet. Its storage and credentials were not touched; restoring this row restores sign-in.'
  })
}
