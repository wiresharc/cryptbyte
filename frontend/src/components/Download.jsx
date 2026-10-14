import { useState, useEffect, useRef, useCallback } from 'react'
import useTransferStats from './useTransferStats'
import { useParams } from 'react-router-dom'
import { importKey, decryptFile, downloadBlob, concatChunks, readHeader, ENC_CHUNK, ciphertextSize } from '../crypto/encryption'
import { sniff, openEncryptedStream, pullUntil, TAU, concat, readHeaderFrom } from '../crypto/streaming'
import { decodeBundleHeader, hasBundleMagic } from '../crypto/bundle'
import { decompressBlob } from '../crypto/compress'
import { formatBytes, formatCountdown, formatSpeed, formatEta } from '../lib/format'
import usePreview from './usePreview'
import PreviewPanel from './PreviewPanel'

const INLINE_LIMIT = 64 * 1024 * 1024

export default function Download() {
  const { token } = useParams()
  const [fileInfo, setFileInfo] = useState(null)
  const [error, setError] = useState(null)
  const [downloading, setDownloading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [decryptProgress, setDecryptProgress] = useState(0)
  const [bundle, setBundle] = useState(null)
  const [downloadedName, setDownloadedName] = useState(null)
  const [stats, setStats] = useState(null)
  const [expiresIn, setExpiresIn] = useState(null)
  const transfer = useTransferStats()
  const [previewOpen, setPreviewOpen] = useState(false)

  const hash = window.location.hash
  const keyMatch = hash.match(/#key=([^&]+)/)
  const encryptionKey = keyMatch ? keyMatch[1] : null

  const previewHook = usePreview({
    token,
    apiUrl: import.meta.env.CB_API_URL || '',
    encryptionKey,
    fallbackName: fileInfo?.original_name,
    fallbackMime: fileInfo?.file_type,
  })

function safeName(name, fallback) {
  if (!name) return fallback
  const base = String(name).split(/[\\/]/).pop().trim()
  if (!base || base === '.' || base === '..') return fallback
  return base.slice(0, 200)
}

  useEffect(() => {
    fetchFileInfo()
  }, [token])

  const fetchFileInfo = async () => {
    try {
      const res = await fetch(`${import.meta.env.CB_API_URL || ''}/api/info/${token}`)
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        throw new Error(err.error || 'file not found or expired')
      }
      const data = await res.json()
      if (data.encrypted && !encryptionKey) {
        throw new Error('this file is encrypted. the decryption key is missing from the link.')
      }
      setFileInfo(data)
    } catch (err) {
      setError(err.message)
    }
  }

  useEffect(() => {
    if (!fileInfo?.expires_at) return
    const update = () => {
      const ms = new Date(fileInfo.expires_at).getTime() - Date.now()
      setExpiresIn(ms > 0 ? ms : 0)
    }
    update()
    const id = setInterval(update, 1000)
    return () => clearInterval(id)
  }, [fileInfo?.expires_at])

  const handleDownload = async () => {
    setDownloading(true)
    setProgress(0)
    setDecryptProgress(0)
    setStats(null)
    setError(null)
    setBundle(null)
    setDownloadedName(null)

    try {
      const response = await fetch(`${import.meta.env.CB_API_URL || ''}/api/download/${token}`)
      if (!response.ok) throw new Error('download failed')

      const contentLength = +response.headers.get('Content-Length') || 0
      const canStream = typeof window.showSaveFilePicker === 'function'
      const isLarge = contentLength > INLINE_LIMIT

      if (!encryptionKey) {
        const name = fileInfo?.original_name || 'downloaded_file'
        const mime = fileInfo?.file_type || 'application/octet-stream'

        // peek the opening bytes: an unencrypted upload still carries a header when
        // it was compressed, and a bundle carries its manifest right at the front
        const reader = response.body.getReader()
        const firstRead = await reader.read()
        const prefix = firstRead.value ? new Uint8Array(firstRead.value) : new Uint8Array(0)
        const plainHeader = readHeaderFrom(prefix)

        const readAll = async () => {
          const chunks = [prefix]
          let total = prefix.length
          while (true) {
            const { done, value } = await reader.read()
            if (done) break
            chunks.push(value)
            total += value.length
          }
          const out = new Uint8Array(total)
          let off = 0
          for (const c of chunks) { out.set(c, off); off += c.length }
          return out
        }

        if (plainHeader) {
          const raw = await readAll()
          let plain = raw.subarray(plainHeader.consumed)
          if (plainHeader.compressed) {
            transfer.reset(raw.length)
            plain = new Uint8Array(await (await decompressBlob(new Blob([plain]))).arrayBuffer())
          }
          const finalName = plainHeader.name || name
          const detected = decodeBundleHeader(plain)
          if (detected) {
            setBundle({ entries: detected.entries, data: plain.subarray(detected.consumed) })
            setDownloadedName(finalName)
            setStats(transfer.tick(plain.length, plain.length))
            setProgress(100)
            setDecryptProgress(100)
            return
          }
          setStats(transfer.tick(plain.length, plain.length))
          downloadBlob([plain], finalName, plainHeader.type || mime)
          setProgress(100)
          setDecryptProgress(100)
          setDownloadedName(finalName)
          return
        }

        // a bundle has to be buffered whole: entry offsets only resolve once
        // every file is present
        if (hasBundleMagic(prefix)) {
          const raw = await readAll()
          const detected = decodeBundleHeader(raw)
          if (detected) {
            transfer.reset(raw.length)
            setBundle({ entries: detected.entries, data: raw.subarray(detected.consumed) })
            setStats(transfer.tick(raw.length, raw.length))
            setDownloadedName(name)
            setProgress(100)
            setDecryptProgress(100)
            return
          }
          downloadBlob([raw], name, mime)
          setStats(transfer.tick(raw.length, raw.length))
          setProgress(100)
          setDecryptProgress(100)
          setDownloadedName(name)
          return
        }

        if (canStream && isLarge) {
          const handle = await window.showSaveFilePicker({ suggestedName: name })
          const writable = await handle.createWritable()
          transfer.reset(contentLength)
          if (prefix.length) await writable.write(prefix)
          const snapFirst = transfer.tick(prefix.length, contentLength)
          if (snapFirst) {
            setStats(snapFirst)
            if (contentLength) setProgress(Math.min(100, Math.round((snapFirst.received / contentLength) * 100)))
          }
          while (true) {
            const { done, value } = await reader.read()
            if (done) break
            await writable.write(value)
            const snap = transfer.tick(value.length, contentLength)
            if (snap) {
              setStats(snap)
              if (contentLength) setProgress(Math.min(100, Math.round((snap.received / contentLength) * 100)))
            }
          }
          await writable.close()
        } else {
          transfer.reset(contentLength)
          const buf = await readAll()
          setStats(transfer.tick(buf.length, buf.length))
          downloadBlob([buf], name, mime)
        }

        setProgress(100)
        setDownloadedName(name)
        return
      }

      const { cryptoKey, baseNonce } = await importKey(encryptionKey)
      const probe = await sniff(response, cryptoKey, baseNonce)

      if (!probe.header) throw new Error('file header is malformed')

      transfer.reset(contentLength)

      // a compressed bundle hides its manifest behind the gzip layer, so it can only be
      // identified after decompressing, which forces it down the buffered path
      const isCompressed = probe.header.compressed
      const bundleInfo = !isCompressed && probe.firstPlain
        ? decodeBundleHeader(probe.firstPlain)
        : null

      if (bundleInfo || isCompressed || !canStream || !isLarge) {
        const parts = []
        let decryptedBytes = 0
        const stream = await openEncryptedStream(
          probe.reader, probe.prefix, cryptoKey, baseNonce, () => {},
          probe.firstPlain
        )
        for await (const part of stream.read()) {
          parts.push(part.bytes)
          decryptedBytes += part.bytes.length
          if (contentLength) {
            setDecryptProgress(Math.min(100, Math.round((decryptedBytes / contentLength) * 100)))
          }
          const snap = transfer.tick(part.bytes.length, contentLength)
          if (snap) setStats(snap)
        }

        let plain = concat(parts)

        if (isCompressed) {
          plain = new Uint8Array(await (await decompressBlob(new Blob([plain]))).arrayBuffer())
        }

        const detected = bundleInfo || decodeBundleHeader(plain)

        if (detected) {
          setBundle({ entries: detected.entries, data: plain.subarray(detected.consumed) })
          setDownloadedName(probe.header.name || 'bundle')
          setProgress(100)
          return
        }

        downloadBlob(
          [plain],
          probe.header.name || 'downloaded_file',
          probe.header.type || 'application/octet-stream'
        )
        setDownloadedName(probe.header.name || 'downloaded_file')
        setProgress(100)
        return
      }

      const handle = await window.showSaveFilePicker({
        suggestedName: probe.header.name || 'download',
      })
      const writable = await handle.createWritable()

      if (probe.header.compressed) {
        const ds = new DecompressionStream('gzip')

        // the output has to be drained while input is still being written, otherwise
        // the transform backs up and write() never resolves. pipeTo would do this for
        // us, but a FileSystemWritableFileStream is not a WritableStream
        const out = ds.readable.getReader()
        const drain = (async () => {
          while (true) {
            const { done, value } = await out.read()
            if (done) break
            await writable.write(value)
          }
        })()

        const writer = ds.writable.getWriter()
        const stream = await openEncryptedStream(
          probe.reader, probe.prefix, cryptoKey, baseNonce,
          () => {}, probe.firstPlain
        )
        for await (const part of stream.read()) {
          await writer.write(part.bytes)
          const snap = transfer.tick(part.bytes.length, contentLength)
          if (snap) {
            setStats(snap)
            if (contentLength) setProgress(Math.min(100, Math.round((snap.received / contentLength) * 100)))
          }
        }
        await writer.close()
        await drain
        await writable.close()
      } else {
        const stream = await openEncryptedStream(
          probe.reader, probe.prefix, cryptoKey, baseNonce,
          () => {}, probe.firstPlain
        )
        for await (const part of stream.read()) {
          await writable.write(part.bytes)
          const snap = transfer.tick(part.bytes.length, contentLength)
          if (snap) {
            setStats(snap)
            if (contentLength) setProgress(Math.min(100, Math.round((snap.received / contentLength) * 100)))
          }
        }
        await writable.close()
      }

      setProgress(100)
      setDownloadedName(probe.header.name || 'download')
    } catch (err) {
      if (err && err.name === 'AbortError') {
        setError('download cancelled')
      } else {
        setError(err.message || 'download failed')
      }
    }

    setDownloading(false)
  }

  const [savingAll, setSavingAll] = useState(false)
  const [savedAll, setSavedAll] = useState(false)

  const saveBundleEntry = async (entry) => {
    if (!bundle) return
    const slice = bundle.data.subarray(entry.o, entry.o + entry.s)
    const name = entry.n.split('/').pop() || 'file'
    try {
      const handle = await window.showSaveFilePicker({ suggestedName: name })
      const writable = await handle.createWritable()
      await writable.write(slice)
      await writable.close()
    } catch (err) {
      if (err && err.name === 'AbortError') return
      downloadBlob([slice], name)
    }
  }

  // chromium can write the whole tree into one directory pick, everywhere else
  // falls back to saving each entry in turn
  const saveAllEntries = async () => {
    if (!bundle || savingAll) return
    setSavingAll(true)
    setSavedAll(false)

    try {
      if (typeof window.showDirectoryPicker === 'function') {
        const dir = await window.showDirectoryPicker({ mode: 'readwrite' })
        for (const entry of bundle.entries) {
          const name = entry.n.split('/').pop() || 'file'
          const handle = await dir.getFileHandle(name, { create: true })
          const writable = await handle.createWritable()
          await writable.write(bundle.data.subarray(entry.o, entry.o + entry.s))
          await writable.close()
        }
      } else {
        for (const entry of bundle.entries) {
          await saveBundleEntry(entry)
        }
      }
      setSavedAll(true)
    } catch (err) {
      if (!err || err.name !== 'AbortError') setError(err.message || 'could not save the files')
    } finally {
      setSavingAll(false)
    }
  }

  const formatSize = (bytes) => {
    if (!bytes) return 'unknown'
    if (bytes < 1024) return bytes + ' b'
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' kb'
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' mb'
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' gb'
  }

  if (error) {
    return (
      <div className="min-h-screen pt-24 pb-16 px-4 flex items-center justify-center">
        <div className="glass p-8 max-w-md w-full text-center">
            <div className="w-16 h-16 mx-auto mb-6 rounded-2xl bg-red-500/10 flex items-center justify-center">
              <svg className="w-8 h-8 text-red-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}>
                <path d="M12 2 L22 12 L12 22 L2 12 Z" strokeLinejoin="round"/>
                <circle cx="12" cy="12" r="3" fill="currentColor"/>
              </svg>
            </div>
          <h2 className="text-xl font-semibold mb-2">download unavailable</h2>
          <p className="text-gray-400">{error}</p>
        </div>
      </div>
    )
  }

  if (!fileInfo) {
    return (
      <div className="min-h-screen pt-24 pb-16 px-4 flex items-center justify-center">
        <div className="glass p-8 max-w-md w-full text-center">
          <div className="w-16 h-16 mx-auto mb-6 rounded-2xl bg-surface-700/50 flex items-center justify-center animate-pulse">
            <svg className="w-8 h-8 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
          </div>
          <p className="text-gray-400">loading file info...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen pt-24 pb-16 px-4 flex items-center justify-center">
      <div className="max-w-lg w-full">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold mb-2">ready to download</h1>
          <p className="text-gray-400">
            {expiresIn !== null && (
              <>available for {formatCountdown(expiresIn)} &middot; </>
            )}
            {fileInfo?.downloads}/{fileInfo?.max_downloads} downloads used
          </p>
        </div>

        <div className="border border-red-500/20 rounded-2xl p-1 mb-6">
          <div className="rounded-2xl bg-surface-800/40 p-6">
            <div className="flex items-center gap-4 mb-6">
              <div className="w-14 h-14 rounded-2xl bg-red-500/10 flex items-center justify-center shrink-0">
                <svg className="w-7 h-7 text-red-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}>
                  <path d="M12 2 L22 12 L12 22 L2 12 Z" strokeLinejoin="round"/>
                  <circle cx="12" cy="12" r="3" fill="currentColor"/>
                </svg>
              </div>
              <div className="min-w-0">
                <p className="font-medium truncate">shared file</p>
                <p className="text-sm text-gray-500">{formatSize(fileInfo.size)}</p>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 mb-6">
              <div className="p-3 rounded-xl bg-surface-700/30 border border-white/5">
                <p className="text-xs text-gray-500 mb-1">file type</p>
                <p className="text-sm font-medium truncate">{fileInfo.file_type || 'unknown'}</p>
              </div>
              <div className="p-3 rounded-xl bg-surface-700/30 border border-white/5">
                <p className="text-xs text-gray-500 mb-1">expires in</p>
                <p className="text-sm font-medium">
                  {expiresIn === null ? '--' : formatCountdown(expiresIn)}
                </p>
              </div>
              <div className="p-3 rounded-xl bg-surface-700/30 border border-white/5">
                <p className="text-xs text-gray-500 mb-1">downloads left</p>
                <p className="text-sm font-medium">
                  {fileInfo.max_downloads - fileInfo.downloads}
                </p>
              </div>
              <div className="p-3 rounded-xl bg-surface-700/30 border border-white/5">
                <p className="text-xs text-gray-500 mb-1">encryption</p>
                <p className="text-sm font-medium">
                  {encryptionKey ? 'aes 256 gcm' : 'none'}
                </p>
              </div>
            </div>

            {downloading && stats && stats.total > 0 && (
        <div className="glass p-4 mb-4">
          <div className="flex flex-wrap justify-between gap-x-6 gap-y-1 text-xs text-gray-400 tabular-nums">
            <span>
              {formatBytes(stats.received)} of {formatBytes(stats.total)}
            </span>
            <span>{formatSpeed(stats.rate)}</span>
            <span>{formatEta(stats.etaMs)} left</span>
            <span className="text-gray-500">
              {formatEta(stats.elapsedMs)} elapsed
            </span>
          </div>
        </div>
      )}

      {downloading && (
              <div className="mb-6 space-y-3">
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span className="text-gray-400">downloading...</span>
                    <span className="text-red-400">{progress}%</span>
                  </div>
                  <div className="progress-bar">
                    <div className="progress-fill" style={{ width: `${progress}%` }} />
                  </div>
                </div>
                {encryptionKey && (
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span className="text-gray-400">decrypting...</span>
                      <span className="text-red-400">{decryptProgress}%</span>
                    </div>
                    <div className="progress-bar">
                      <div className="progress-fill" style={{ width: `${decryptProgress}%` }} />
                    </div>
                  </div>
                )}
              </div>
            )}

            {previewOpen && (
              <div className="mb-6">
                <PreviewPanel hook={previewHook} onClose={() => setPreviewOpen(false)} />
              </div>
            )}

            <button
              onClick={handleDownload}
              disabled={downloading}
              className="btn-primary w-full py-4 text-lg"
            >
              {downloading ? 'processing...' : bundle ? 'decrypt bundle' : 'download file'}
            </button>

            <button
              onClick={() => { previewHook.requestSingle(); setPreviewOpen(true) }}
              disabled={downloading}
              className="mt-2 w-full py-2 rounded-xl bg-surface-700/40 hover:bg-surface-700
                         border border-white/5 text-sm text-gray-400 transition-colors
                         disabled:opacity-50"
            >
              preview
            </button>

            {bundle && (
              <div className="mt-6">
                <div className="flex items-center justify-between gap-2 mb-3">
                  <p className="text-xs text-gray-500 uppercase tracking-wider">
                    {bundle.entries.length} files
                  </p>
                  <button
                    onClick={saveAllEntries}
                    disabled={savingAll}
                    className="px-3 py-1.5 rounded-lg bg-red-500 hover:bg-red-600 text-xs
                               transition-colors disabled:opacity-50"
                  >
                    {savingAll ? 'saving...' : 'download all files'}
                  </button>
                </div>
                {savedAll && (
                  <p className="text-xs text-green-400 mb-2">all files saved</p>
                )}
                <ul className="space-y-1">
                  {bundle.entries.map((entry, i) => (
                    <li key={i}>
                      <button
                        onClick={() => saveBundleEntry(entry)}
                        className="w-full text-left px-3 py-2 rounded-lg bg-surface-700/40 border border-white/5 hover:bg-surface-700 text-sm transition-colors"
                      >
                        <span className="block truncate">{entry.n}</span>
                        <span className="text-xs text-gray-500">{formatSize(entry.s)}</span>
                      </button>
                      <button
                        onClick={() => { previewHook.requestEntry(entry, bundle.data); setPreviewOpen(true) }}
                        aria-label={`preview ${entry.n}`}
                        className="mt-1 w-full py-1 rounded-lg bg-surface-700/20 border border-white/5
                                   hover:bg-surface-700/60 text-xs text-gray-500 transition-colors"
                      >
                        preview
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {encryptionKey && (
              <p className="text-xs text-gray-600 text-center mt-3">
                this file is end to end encrypted. decryption happens in your browser.
              </p>
            )}
          </div>
        </div>
      </div>

    </div>
  )
}
