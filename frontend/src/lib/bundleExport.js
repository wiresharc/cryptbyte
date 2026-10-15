// Bulk export for a decrypted bundle.
//
// Three problems this has to solve at once:
//  1. browsers block multiple automatic downloads, so N anchor clicks turn into
//     one file. phones block them even harder.
//  2. building a Blob per entry copies, so 47 entries would double the memory
//     already held by a decrypted bundle. on a phone that is an oom.
//  3. entry names come from the sender, so an untrusted bundle can carry
//     traversal sequences that some extractors will happily write to disk.

const SCRATCH = 'cryptbyte-export'

export function canPickFolder() {
  return typeof window !== 'undefined' && typeof window.showDirectoryPicker === 'function'
}

export function canShareFiles() {
  return (
    typeof navigator !== 'undefined' &&
    typeof navigator.canShare === 'function' &&
    typeof navigator.share === 'function'
  )
}

// strips anything that could escape the extraction directory
export function safePath(name, index) {
  const parts = String(name || '')
    .replace(/\\/g, '/')
    .split('/')
    .map((p) => p.trim())
    .filter((p) => p && p !== '.' && p !== '..' && !/^[a-zA-Z]:/.test(p))

  const clean = parts.join('/')
  if (!clean) return `file-${index + 1}`
  return clean.length > 180 ? clean.slice(-180) : clean
}

const IMAGE_EXT = /\.(png|jpe?g|gif|webp|bmp|heic|heif|avif|tiff?)$/i
const VIDEO_EXT = /\.(mp4|mov|m4v|webm|avi|mkv|3gp)$/i

// the share sheet only offers targets that accept every file in the set, so a
// bundle containing a pdf will silently lose the photo gallery as an option
export function bundleMediaKind(entries) {
  if (!entries.length) return 'empty'
  let images = 0
  let videos = 0
  for (const e of entries) {
    if (IMAGE_EXT.test(e.n)) images++
    else if (VIDEO_EXT.test(e.n)) videos++
    else return 'mixed'
  }
  if (images && !videos) return 'images'
  if (videos && !images) return 'videos'
  return 'mixed'
}

function opfsRoot() {
  if (typeof navigator === 'undefined' || !navigator.storage?.getDirectory) return null
  return navigator.storage.getDirectory()
}

async function withScratchDir(fn) {
  const root = await opfsRoot()
  if (!root) return fn(null)

  let dir = null
  try {
    dir = await root.getDirectoryHandle(SCRATCH, { create: true })
  } catch {
    return fn(null)
  }
  try {
    return await fn(dir)
  } finally {
    try {
      await root.removeEntry(SCRATCH, { recursive: true })
    } catch {}
  }
}

// writes each entry to disk so the share sheet gets disk backed File objects and
// nothing is copied out of the already decrypted bundle
async function stage(entries, data, dir, onProgress) {
  const files = []
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i]
    const path = safePath(entry.n, i)
    const name = path.split('/').pop()
    const bytes = data.subarray(entry.o, entry.o + entry.s)

    if (dir) {
      try {
        const fh = await dir.getFileHandle(name, { create: true })
        const w = await fh.createWritable()
        await w.write(bytes)
        await w.close()
        files.push({ path, file: new File([await fh.getFile()], name) })
        onProgress?.(i + 1, entries.length)
        continue
      } catch {
        // fall through for this entry
      }
    }
    files.push({ path, file: new File([bytes], name) })
    onProgress?.(i + 1, entries.length)
  }
  return files
}

export async function shareBundle(entries, data, onProgress) {
  if (!canShareFiles()) throw new Error('sharing is not supported in this browser')

  return withScratchDir(async (dir) => {
    const files = await stage(entries, data, dir, onProgress)
    if (!navigator.canShare({ files })) {
      throw new Error('too many files to send at once')
    }
    await navigator.share({ files })
  })
}

// stored entries, not deflate: these files were already compressed when the
// sender chose compression, so deflating again only burns battery for nothing.
// reads straight from the decrypted bundle so nothing is duplicated on the way.
export async function zipBundle(entries, data, zipName) {
  const { zipSync } = await import('fflate')

  const files = {}
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i]
    const path = safePath(entry.n, i)
    // a later entry could collide with an earlier one after sanitising
    files[path] = data.subarray(entry.o, entry.o + entry.s)
  }

  const archive = zipSync(files, { level: 0 })
  return new File([archive], zipName, { type: 'application/zip' })
}

export async function saveToFolder(entries, data, onProgress) {
  const dir = await window.showDirectoryPicker({ mode: 'readwrite' })
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i]
    const name = safePath(entry.n, i).split('/').pop()
    const handle = await dir.getFileHandle(name, { create: true })
    const writable = await handle.createWritable()
    await writable.write(data.subarray(entry.o, entry.o + entry.s))
    await writable.close()
    onProgress?.(i + 1, entries.length)
  }
}
