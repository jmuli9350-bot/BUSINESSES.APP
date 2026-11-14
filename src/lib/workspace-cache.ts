type CachedWorkspaceSnapshot = {
  tenantId: string
  payload: unknown
  updatedAt: string | null
  cachedAt: string
}

const databaseName = 'biztrack-offline-cache'
const storeName = 'workspace-snapshots'

const openDatabase = () => new Promise<IDBDatabase>((resolve, reject) => {
  const request = indexedDB.open(databaseName, 1)
  request.onupgradeneeded = () => {
    if (!request.result.objectStoreNames.contains(storeName)) {
      request.result.createObjectStore(storeName, { keyPath: 'tenantId' })
    }
  }
  request.onsuccess = () => resolve(request.result)
  request.onerror = () => reject(request.error || new Error('Could not open the offline workspace cache.'))
})

export const readCachedWorkspaceSnapshot = async (tenantId: string): Promise<CachedWorkspaceSnapshot | null> => {
  const database = await openDatabase()
  try {
    return await new Promise((resolve, reject) => {
      const request = database.transaction(storeName, 'readonly').objectStore(storeName).get(tenantId)
      request.onsuccess = () => resolve((request.result as CachedWorkspaceSnapshot | undefined) ?? null)
      request.onerror = () => reject(request.error || new Error('Could not read the offline workspace cache.'))
    })
  } finally {
    database.close()
  }
}

export const cacheWorkspaceSnapshot = async (tenantId: string, payload: unknown, updatedAt: string | null) => {
  const database = await openDatabase()
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(storeName, 'readwrite')
      transaction.objectStore(storeName).put({ tenantId, payload, updatedAt, cachedAt: new Date().toISOString() } satisfies CachedWorkspaceSnapshot)
      transaction.oncomplete = () => resolve()
      transaction.onerror = () => reject(transaction.error || new Error('Could not save the offline workspace cache.'))
      transaction.onabort = () => reject(transaction.error || new Error('Offline workspace cache save was aborted.'))
    })
  } finally {
    database.close()
  }
}
