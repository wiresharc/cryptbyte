import { useState, useRef, useCallback, useEffect } from 'react'
import { importKey } from '../crypto/encryption'
import { sniff, openEncryptedStream, concat } from '../crypto/streaming'
import { decompressBlob } from '../crypto/compress'

// rendering is the dangerous part, not downloading: a decoded bitmap runs several
// times larger than its jpeg and a pdf viewer lays out every page up front, so the
// caps are per kind rather than one flat ceiling
export const PREVIEW_TEXT_LIMIT = 5 * 1024 * 1024
export const PREVIEW_IMAGE_LIMIT = 20 * 1024 * 1024
export const PREVIEW_PDF_LIMIT = 25 * 1024 * 1024
export const PREVIEW_MEDIA_LIMIT = 25 * 1024 * 1024
export const PREVIEW_BYTE_LIMIT = 25 * 1024 * 1024

const LIMIT_FOR = {
  text: PREVIEW_TEXT_LIMIT,
  image: PREVIEW_IMAGE_LIMIT,
  pdf: PREVIEW_PDF_LIMIT,
  audio: PREVIEW_MEDIA_LIMIT,
  video: PREVIEW_MEDIA_LIMIT,
  blocked: 0,
  binary: 0,
}

export function limitFor(kind) {
  return LIMIT_FOR[kind] ?? PREVIEW_BYTE_LIMIT
}

const TEXT_TYPES = /^text\/|json|javascript|xml|yaml|x-sh|x-httpd|csv|markdown|sql|toml|ini|rtf|javascript|ecmascript|x-python|x-c|x-go|x-rust|x-php|x-ruby|x-perl|x-shellscript/
// browsers report application/octet-stream for plenty of plain text files
// (.ts, .json, .log and so on), so the extension has to be able to vouch for it
const TEXT_EXT = /\.(txt|text|log|md|markdown|csv|json|jsonl|xml|ya?ml|toml|ini|cfg|conf|env|ts|tsx|js|jsx|mjs|cjs|c|h|cc|cpp|hpp|cs|go|rs|rb|py|php|java|kt|swift|scala|sh|bash|zsh|fish|sql|graphql|vue|svelte|astro|dockerfile|gitignore|properties|lock|diff|patch)$/i
const IMAGE_TYPES = /^image\/(png|jpeg|jpg|gif|webp|bmp|x-icon|avif)/
const AUDIO_TYPES = /^audio\//
const VIDEO_TYPES = /^video\//

// user markup must never execute in our origin: it could read the key from the
// url fragment and exfiltrate the file. svg is deliberately absent, it only ever
// reaches the dom through <img> which does not run scripts.
const FORBIDDEN = /^(text\/html|application\/xhtml|image\/svg)/i

export function classify(name, type) {
  const mime = (type || '').toLowerCase()
  if (FORBIDDEN.test(mime) || /\.(html?|xhtml|svg)$/i.test(name || '')) return 'blocked'
  if (IMAGE_TYPES.test(mime) || /\.(png|jpe?g|gif|webp|bmp|avif|ico)$/i.test(name || '')) return 'image'
  if (AUDIO_TYPES.test(mime)) return 'audio'
  if (VIDEO_TYPES.test(mime)) return 'video'
  if (mime === 'application/pdf' || /\.pdf$/i.test(name || '')) return 'pdf'
  if (TEXT_TYPES.test(mime) || TEXT_EXT.test(name || '')) return 'text'
  return 'binary'
}

export default function usePreview({ token, apiUrl, encryptionKey, fallbackName, fallbackMime }) {
  const [preview, setPreview] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [target, setTarget] = useState(null)
  const abortRef = useRef(null)
  const urlRef = useRef(null)

  const releaseUrl = useCallback(() => {
    if (urlRef.current) {
      URL.revokeObjectURL(urlRef.current)
      urlRef.current = null
    }
  }, [])

  const clear = useCallback(() => {
    if (abortRef.current) abortRef.current.abort()
    releaseUrl()
    setPreview(null)
    setLoading(false)
    setError(null)
    setTarget(null)
  }, [releaseUrl])

  useEffect(() => () => {
    if (abortRef.current) abortRef.current.abort()
    releaseUrl()
  }, [releaseUrl])

  // single file, decrypted straight into one buffer
  const openSingle = useCallback(async () => {
    const controller = new AbortController()
    abortRef.current = controller
    setLoading(true)
    setError(null)
    releaseUrl()
    setPreview(null)

    try {
      const res = await fetch(`${apiUrl}/api/download/${token}?preview=1`, {
        signal: controller.signal,
      })
      if (!res.ok) throw new Error('preview failed')

      const contentLength = +res.headers.get('Content-Length') || 0
      // an encrypted file's server-side type describes the ciphertext, so the real
      // name and type only come out of the header once it has been decrypted
      let name = fallbackName || ''
      let mime = fallbackMime || ''

      if (!encryptionKey) {
        const kind = classify(name, mime)
        if (limitFor(kind) === 0) {
          setError(kind === 'blocked'
            ? 'this file type cannot be previewed safely'
            : 'no preview for this file type')
          setLoading(false)
          return
        }
        if (contentLength && contentLength > limitFor(kind)) {
          setError('too large to preview')
          setLoading(false)
          return
        }
        const bytes = new Uint8Array(await res.arrayBuffer())
        return finish(bytes, name, mime)
      }

      const { cryptoKey, baseNonce } = await importKey(encryptionKey)
      const probe = await sniff(res, cryptoKey, baseNonce)
      if (!probe.header) throw new Error('bad header')
      name = probe.header.name || ''
      mime = probe.header.type || ''

      // decrypt into a single preallocated buffer instead of collecting chunks and
      // concatenating, which would briefly hold two full copies of the plaintext
      const kind = classify(name, mime)
      const kindLimit = limitFor(kind)

      if (kindLimit === 0) {
        setError(kind === 'blocked'
          ? 'this file type cannot be previewed safely'
          : 'no preview for this file type')
        setLoading(false)
        return
      }

      // a known ciphertext length above the cap means the plaintext is far past it
      // too, so bail before pulling hundreds of megabytes over the wire
      if (contentLength && contentLength > kindLimit && !probe.header.compressed) {
        setError('too large to preview')
        setLoading(false)
        return
      }

      let target = probe.header.compressed
        ? Math.min(contentLength || kindLimit * 4, kindLimit * 4)
        : (contentLength || kindLimit)

      const cap = Math.min(target, kindLimit)
      const buf = new Uint8Array(Math.max(cap, 1))
      let offset = 0
      let full = true

      const stream = await openEncryptedStream(
        probe.reader, probe.prefix, cryptoKey, baseNonce, () => {}, probe.firstPlain
      )

      try {
        for await (const part of stream.read()) {
          if (offset + part.bytes.length > buf.length) {
            full = false
            break
          }
          buf.set(part.bytes, offset)
          offset += part.bytes.length
        }
      } catch (err) {
        if (err && err.name === 'AbortError') return
        throw err
      }

      let bytes = buf.subarray(0, offset)

      if (probe.header.compressed) {
        try {
          bytes = new Uint8Array(
            await (await decompressBlob(new Blob([bytes]))).arrayBuffer()
          )
        } catch {
          bytes = null
        }
      }

      if (!bytes) {
        setError('could not decompress for preview')
        setLoading(false)
        return
      }
      if (!full && !probe.header.compressed) {
        setError('too large to preview')
        setLoading(false)
        return
      }

      finish(bytes, name, mime)
    } catch (err) {
      if (err && err.name === 'AbortError') return
      setError(err.message || 'preview failed')
      setLoading(false)
    }
  }, [token, apiUrl, encryptionKey, fallbackName, fallbackMime, releaseUrl])

  const finish = (bytes, name, mime) => {
    const kind = classify(name, mime)
    if (kind === 'blocked') {
      setError('this file type cannot be previewed safely')
      setLoading(false)
      return
    }
    if (kind === 'binary') {
      setError('no preview for this file type')
      setLoading(false)
      return
    }

    let text = null
    let url = null
    if (kind === 'text') {
      if (bytes.length > PREVIEW_TEXT_LIMIT * 4) {
        setError('too large to preview')
        setLoading(false)
        return
      }
      text = new TextDecoder('utf-8', { fatal: false }).decode(bytes)
    } else {
      url = URL.createObjectURL(new Blob([bytes], { type: mime || 'application/octet-stream' }))
      urlRef.current = url
    }

    setPreview({ name, mime, kind, bytes, text, url, size: bytes.length })
    setLoading(false)
  }

  // bundle entries are already plaintext in memory, so this costs nothing
  const openEntry = useCallback((entry, data) => {
    if (abortRef.current) abortRef.current.abort()
    releaseUrl()
    setError(null)
    setLoading(true)

    const bytes = data.subarray(entry.o, entry.o + entry.s)
    const name = entry.n.split('/').pop() || 'file'
    queueMicrotask(() => {
      try {
        finish(bytes, name, guessMime(name))
      } catch (err) {
        setError(err.message || 'preview failed')
        setLoading(false)
      }
    })
  }, [releaseUrl])

  // nothing is fetched or decrypted until the user explicitly asks for it
  const activate = useCallback(() => {
    const t = target
    if (!t) return
    if (t.kind === 'entry') openEntry(t.entry, t.data)
    else openSingle()
  }, [target, openEntry, openSingle])

  const requestSingle = useCallback(() => setTarget({ kind: 'single' }), [])
  const requestEntry = useCallback((entry, data) => setTarget({ kind: 'entry', entry, data }), [])

  return {
    preview, loading, error, clear, activate,
    ready: Boolean(target),
    requestSingle, requestEntry,
  }
}

function guessMime(name) {
  const ext = (name.split('.').pop() || '').toLowerCase()
  const map = {
    txt: 'text/plain', md: 'text/markdown', json: 'application/json',
    js: 'text/javascript', ts: 'text/javascript', jsx: 'text/javascript',
    tsx: 'text/javascript', html: 'text/html', htm: 'text/html',
    css: 'text/css', csv: 'text/csv', xml: 'text/xml', yml: 'text/yaml',
    yaml: 'text/yaml', svg: 'image/svg+xml', png: 'image/png',
    jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif',
    webp: 'image/webp', pdf: 'application/pdf', mp3: 'audio/mpeg',
    mp4: 'video/mp4', webm: 'video/webm', zip: 'application/zip',
  }
  return map[ext] || 'application/octet-stream'
}