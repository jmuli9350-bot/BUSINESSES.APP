export const DEFAULT_SESSION_IDLE_TIMEOUT_MS = 3 * 60 * 1000

export async function runBulkAttendanceAction(selectedIds, action, processor) {
  let successful = 0

  for (const memberId of selectedIds) {
    const result = await processor(memberId, action)
    if (result !== false) successful += 1
  }

  return successful
}
