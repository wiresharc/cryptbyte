const MANIFEST_MAGIC = 'CBUNDLE1'
const MAX_BUNDLE_ENTRIES = 10000

function encodeBundle(files) {
  const entries = []
  let offset = 0
  for (const file of files) {
    entries.push({ n: file.webkitRelativePath || file.name, s: file.size, o: offset })
    offset += file.size
  }

  const manifest = new TextEncoder().encode(JSON.stringify(entries))
  const magic = new TextEncoder().encode(MANIFEST_MAGIC)

  const len = new Uint8Array(4)
  new DataView(len.buffer).setUint32(0, manifest.length, false)

  return {
    manifestBlob: new Blob([magic, len, manifest]),
    dataSize: offset,
    count: entries.length,
  }
}

function decodeBundleHeader(bytes) {
  const marker = new TextEncoder().encode(MANIFEST_MAGIC)
  if (bytes.length < marker.length) return null
  for (let i = 0; i < marker.length; i++) {
    if (bytes[i] !== marker[i]) return null
  }

  if (bytes.length < marker.length + 4) return null

  const len = new DataView(bytes.buffer, bytes.byteOffset + marker.length, 4).getUint32(0, false)
  const start = marker.length + 4
  if (len === 0 || start + len > bytes.length) return null

  try {
    const entries = JSON.parse(new TextDecoder().decode(bytes.subarray(start, start + len)))
    if (!Array.isArray(entries) || entries.length === 0) return null
    // the manifest comes from whoever uploaded the bundle, so a hostile sender
    // could declare millions of entries and make every recipient loop forever when
    // they try to save or zip the bundle
    if (entries.length > MAX_BUNDLE_ENTRIES) return null
    return { entries, consumed: start + len }
  } catch {
    return null
  }
}

// cheap check on the opening bytes so a download knows whether it must buffer
export function hasBundleMagic(bytes) {
  if (!bytes || bytes.length < MANIFEST_MAGIC.length) return false
  const magic = new TextEncoder().encode(MANIFEST_MAGIC)
  for (let i = 0; i < magic.length; i++) {
    if (bytes[i] !== magic[i]) return false
  }
  return true
}

export { encodeBundle, decodeBundleHeader }