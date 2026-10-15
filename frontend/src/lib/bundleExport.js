// Bundle export.
//
// A bundle is always handed over as a single archive. Browsers block multiple
// automatic downloads, so N separate files means one file on most devices, and
// the only portable way out is one archive the recipient extracts themselves.
//
// Entries are STORED rather than deflated: the payloads were already compressed
// when the sender chose compression, so deflating again only burns battery for
// nothing. That also means the archive can never expand on extraction, since its
// ratio is always about 1:1.

const MIME = {
  jpg: 'image/jpeg', jpeg: 'image/jpeg', jfif: 'image/jpeg', png: 'image/png',
  gif: 'image/gif', webp: 'image/webp', bmp: 'image/bmp', tif: 'image/tiff',
  tiff: 'image/tiff', heic: 'image/heic', heif: 'image/heif', avif: 'image/avif',
  mp4: 'video/mp4', m4v: 'video/mp4', mov: 'video/quicktime', webm: 'video/webm',
  mp3: 'audio/mpeg', m4a: 'audio/mp4', aac: 'audio/aac', wav: 'audio/wav',
  ogg: 'audio/ogg', flac: 'audio/flac', pdf: 'application/pdf',
  txt: 'text/plain', log: 'text/plain', md: 'text/markdown', csv: 'text/csv',
  json: 'application/json', xml: 'application/xml', html: 'text/html',
  js: 'text/javascript', mjs: 'text/javascript', ts: 'text/javascript',
  jsx: 'text/javascript', tsx: 'text/javascript', css: 'text/css',
  yaml: 'text/yaml', yml: 'text/yaml', py: 'text/x-python', sh: 'text/x-sh',
}

export function mimeFor(name) {
  const ext = String(name || '').split('.').pop().toLowerCase()
  return MIME[ext] || 'application/octet-stream'
}

// entry names come from the sender, so an untrusted bundle can carry traversal
// sequences that some extractors will happily write to disk
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

// reads straight out of the decrypted bundle so nothing is duplicated on the way
export async function zipBundle(entries, data, zipName = 'bundle.zip') {
  const { zipSync } = await import('fflate')

  const files = {}
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i]
    // a later entry could collide with an earlier one once sanitised
    files[safePath(entry.n, i)] = data.subarray(entry.o, entry.o + entry.s)
  }

  return new File([zipSync(files, { level: 0 })], zipName, { type: 'application/zip' })
}
