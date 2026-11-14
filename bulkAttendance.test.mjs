import assert from 'node:assert/strict'
import test from 'node:test'
import { runBulkAttendanceAction } from './src/bulkAttendance.js'

test('bulk attendance actions run sequentially and count only successful updates', async () => {
  const processed = []
  const result = await runBulkAttendanceAction([101, 102, 103], 'Sign in', async (memberId) => {
    processed.push(memberId)
    if (memberId === 102) return false
    return true
  })

  assert.equal(result, 2)
  assert.deepEqual(processed, [101, 102, 103])
})
