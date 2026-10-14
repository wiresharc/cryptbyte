import ExpirySelector, { DEFAULT_EXPIRY_SECONDS } from './ExpirySelector'
import EncryptionPolicyModal from './EncryptionPolicyModal'
import { useState, useCallback, useRef, useEffect } from 'react'
import { generateKeyMaterial, exportKey, importKey } from '../crypto/encryption'
import { encodeBundle } from '../crypto/bundle'
import { removeOpfsFile } from '../crypto/compress'
import { uploadBlob, preparePayload, readPendingUpload, clearPendingUpload } from '../api/upload'
import DownloadLookup from './DownloadLookup'
import { filesFromDrop, mergeFiles, totalSize } from '../api/files'

const MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024

const formatLimit = (bytes) => (bytes / 1024 / 1024 / 1024).toFixed(0) + ' gb'


export default function Upload() {
  const [file, setFile] = useState(null)
  const [uploading, setUploading] = useState(false)
  const [uploadStats, setUploadStats] = useState(null)
  const [useEncryption, setUseEncryption] = useState(true)
  const [showPolicy, setShowPolicy] = useState(false)
  const [downloadMode, setDownloadMode] = useState('single')
  const [expirySeconds, setExpirySeconds] = useState(DEFAULT_EXPIRY_SECONDS)

  const [result, setResult] = useState(null)

  const expiresLabel = (() => {
    const parsed = result?.expires ? new Date(result.expires) : null
    const when = parsed && !isNaN(parsed.getTime()) ? parsed : new Date(Date.now() + expirySeconds * 1000)
    return when.toLocaleString()
  })()

  const [error, setError] = useState(null)
  const [dragOver, setDragOver] = useState(false)
  const [captchaVerified, setCaptchaVerified] = useState(false)
  const [captchaToken, setCaptchaToken] = useState(null)
  const fileInputRef = useRef(null)
  const honeypotRef = useRef(null)
  const abortRef = useRef(null)
  const [bundleFiles, setBundleFiles] = useState([])
  const [bundleDragOver, setBundleDragOver] = useState(false)
  const [useCompression, setUseCompression] = useState(false)
  const [bundleName, setBundleName] = useState('')
  const [pending, setPending] = useState(null)
  const [resuming, setResuming] = useState(false)
  const [prepared, setPrepared] = useState(null)
  const [preparing, setPreparing] = useState(false)
  const [rawSize, setRawSize] = useState(0)

  useEffect(() => {
    setPending(readPendingUpload())
  }, [])

  const activeFiles = bundleFiles.length > 0 ? bundleFiles : file ? [file] : []
  const compressing = useCompression
  const effectiveSize = compressing && prepared ? prepared.final : rawSize
  const overLimit = effectiveSize > MAX_FILE_SIZE

  const buildPayload = useCallback((chosen, name) => {
    if (chosen.length > 1) {
      const { manifestBlob, dataSize, count } = encodeBundle(chosen)
      return {
        blob: new Blob([manifestBlob, ...chosen]),
        displayName: (name || 'bundle').replace(/\.[a-z0-9]+$/i, '') + '.cryptbyte',
        bundleEntries: { count, dataSize },
      }
    }
    return { blob: chosen[0], displayName: chosen[0].name, bundleEntries: null }
  }, [])

  useEffect(() => {
    let cancelled = false
    if (!file && bundleFiles.length === 0) {
      setPrepared(null)
      setPreparing(false)
      setRawSize(0)
      return
    }

    const built = buildPayload(activeFiles, bundleName)
    const raw = built.blob.size

    setRawSize(raw)

    if (!useCompression) {
      setPrepared({ blob: null, raw, final: raw, spilled: false })
      setPreparing(false)
      if (raw > MAX_FILE_SIZE) {
        setError(`file is ${formatBytes(raw)} which exceeds the ${formatLimit(MAX_FILE_SIZE)} limit`)
      } else {
        setError(null)
      }
      return
    }

    setPreparing(true)
    setPrepared(null)

    preparePayload(built.blob, { encrypted: useEncryption, compress: true })
      .then((result) => {
        if (cancelled) return
        setPrepared(result)
        setPreparing(false)
        if (result.final > MAX_FILE_SIZE) {
          setError(`${formatBytes(result.final)} after compression still exceeds the ${formatLimit(MAX_FILE_SIZE)} limit`)
        } else {
          setError(null)
        }
      })
      .catch(() => {
        if (!cancelled) { setPreparing(false); setPrepared(null) }
      })

    return () => { cancelled = true }
  }, [file, bundleFiles, useCompression, useEncryption, buildPayload])

  const handleFile = useCallback((f) => {
    if (!f) return
    setFile(f)
    setBundleFiles([])
    setResult(null)
  }, [])

  const handleDrop = useCallback((e) => {
    e.preventDefault()
    setDragOver(false)
    handleFile(e.dataTransfer.files[0])
  }, [handleFile])

  const addBundleFiles = useCallback((incoming) => {
    if (!incoming || !incoming.length) return
    setBundleFiles((prev) => mergeFiles(prev, incoming))
    setFile(null)
    setResult(null)
  }, [])

  const handleBundleDrop = useCallback(async (e) => {
    e.preventDefault()
    setBundleDragOver(false)
    const dropped = await filesFromDrop(e.dataTransfer)
    addBundleFiles(dropped)
  }, [addBundleFiles])

  const clearBundle = useCallback(() => {
    setBundleFiles([])
    setBundleName('')
  }, [])

  const removeBundleFile = useCallback((index) => {
    setBundleFiles((prev) => prev.filter((_, i) => i !== index))
  }, [])

  const handleUpload = async () => {
    if (!file && bundleFiles.length === 0) return
    if (!captchaVerified) {
      setError('please verify captcha')
      return
    }

    abortRef.current = new AbortController()
    setUploading(true)
    setUploadStats(null)
    setError(null)
    setResult(null)

    try {
      const chosen = bundleFiles.length > 0 ? bundleFiles : [file]
      const built = buildPayload(chosen, bundleName)
      const payload = built.blob
      const displayName = built.displayName
      const bundleEntries = built.bundleEntries

      if (prepared && prepared.final > MAX_FILE_SIZE) {
        setError(
          prepared.raw > MAX_FILE_SIZE
            ? `file is ${formatBytes(prepared.raw)} which exceeds the ${formatLimit(MAX_FILE_SIZE)} limit`
            : `${formatBytes(prepared.final)} after compression still exceeds the ${formatLimit(MAX_FILE_SIZE)} limit`
        )
        setUploading(false)
        return
      }

      let keyFragment = null
      let cryptoKey = null
      let baseNonce = null
      let keyB64 = null
      let resume = null

      const canResume = Boolean(
        resuming && pending && pending.uploadId && pending.keyB64 &&
        !bundleEntries && file && !useCompression &&
        pending.sourceSize === built.blob.size
      )

      if (useEncryption) {
        if (canResume && pending.keyB64) {
          const restored = await importKey(pending.keyB64)
          cryptoKey = restored.cryptoKey
          baseNonce = restored.baseNonce
          keyB64 = pending.keyB64
          resume = { uploadId: pending.uploadId }
          keyFragment = keyB64
        } else {
          const material = await generateKeyMaterial()
          cryptoKey = material.cryptoKey
          baseNonce = material.baseNonce
          keyB64 = exportKey(material.keyBytes, material.baseNonce)
          keyFragment = keyB64
        }
      }

      const response = await uploadBlob(payload, {
        apiUrl: import.meta.env.CB_API_URL || '',
        downloads: downloadMode,
        encrypted: useEncryption,
        cryptoKey,
        baseNonce,
        keyB64,
        name: displayName,
        type: bundleEntries ? 'application/octet-stream' : (chosen[0].type || 'application/octet-stream'),
        compress: useCompression,
        precompressed: resume ? null : prepared?.blob,
        spilled: prepared?.spilled,
        resume,
        captchaToken,
        honeypot: honeypotRef.current?.value || '',
        expiresIn: expirySeconds,
        filename: useEncryption ? 'encrypted.bin' : displayName,
        signal: abortRef.current?.signal,
        onProgress: (stats) => setUploadStats(stats),
      })

      setPrepared(null)
      setResuming(false)
      setPending(null)
      setUploadStats((prev) => (prev ? { ...prev, loaded: prev.total, percent: 100 } : prev))

      const downloadUrl = `${window.location.origin}/download/${response.token}`
      const shareUrl = keyFragment
        ? `${downloadUrl}#key=${keyFragment}`
        : downloadUrl

      setResult({
        url: shareUrl,
        bundleEntries,
        token: response.token,
        key: keyFragment,
        size: response.size,
        fileType: response.fileType,
        expires: response.expires,
      })

    } catch (err) {
      if (err && err.name === 'AbortError') {
        clearPendingUpload()
        setError('upload cancelled')
      } else {
        setError(err.message || 'upload failed')
      }
      setCaptchaToken(null)
      setCaptchaVerified(false)
    } finally {
      removeOpfsFile()
    }
    setUploading(false)
  }

  const [copied, setCopied] = useState(null)
  const copyTimer = useRef(null)

  const copyToClipboard = (key, text) => {
    navigator.clipboard.writeText(text)
    setCopied(key)
    if (copyTimer.current) clearTimeout(copyTimer.current)
    copyTimer.current = setTimeout(() => setCopied(null), 7000)
  }

  useEffect(() => () => {
    if (copyTimer.current) clearTimeout(copyTimer.current)
  }, [])

  const copyBtnClass = (key) => `shrink-0 px-3 py-1.5 rounded-lg text-sm transition-colors
           inline-flex items-center gap-1.5 min-w-[5.5rem] justify-center
           ${copied === key
             ? 'bg-green-500/15 text-green-400'
             : 'bg-surface-600 hover:bg-surface-500 text-white'}`

  return (
    <div className="min-h-screen pt-24 pb-16 px-4">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-12">
          <h1 className="text-4xl sm:text-5xl font-bold mb-4">
            share files <span className="gradient-text text-glow">securely</span>
          </h1>
        </div>

        <div className="grid sm:grid-cols-2 gap-4 mb-8">

          <div
            className={`border rounded-2xl p-1 transition-all duration-300 ${
              dragOver ? 'border-red-500/60 scale-[1.01]' : 'border-red-500/20'
            }`}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
          >
            <div
              className={`rounded-2xl p-8 sm:p-10 text-center h-full flex flex-col transition-all duration-300 cursor-pointer ${
                dragOver ? 'bg-red-500/10' : 'bg-surface-800'
              }`}
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                className="hidden"
                onChange={(e) => handleFile(e.target.files[0])}
              />

              <div className="w-14 h-14 mx-auto mb-5 rounded-xl bg-red-500/10 flex items-center justify-center">
                <svg className="w-7 h-7 text-red-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}>
                  <path d="M12 2 L22 12 L12 22 L2 12 Z" strokeLinejoin="round"/>
                  <circle cx="12" cy="12" r="3" fill="currentColor"/>
                </svg>
              </div>

              <p className="text-xs uppercase tracking-wider text-gray-500 mb-2">single file</p>

              {!file ? (
                <>
                  <p className="font-medium mb-1">drop your file here</p>
                  <p className="text-xs text-gray-600 mt-2">
                    or click to browse &middot; max {formatLimit(MAX_FILE_SIZE)}
                  </p>
                </>
              ) : (
                <>
                  <p className="font-medium mb-1 truncate">{file.name}</p>
                  <p className="text-sm text-gray-500">{formatBytes(file.size)}</p>
                  <button
                    onClick={(e) => { e.stopPropagation(); setFile(null) }}
                    className="mt-4 text-sm text-red-400 hover:text-red-300 transition-colors"
                  >
                    remove
                  </button>
                </>
              )}
            </div>
          </div>

          <div
            className={`border rounded-2xl p-1 transition-all duration-300 ${
              bundleDragOver ? 'border-red-500/60 scale-[1.01]' : 'border-red-500/20'
            }`}
            onDragOver={(e) => { e.preventDefault(); setBundleDragOver(true) }}
            onDragLeave={() => setBundleDragOver(false)}
            onDrop={handleBundleDrop}
          >
            <div
              className={`rounded-2xl p-8 sm:p-10 text-center h-full flex flex-col transition-all duration-300 ${
                bundleDragOver ? 'bg-red-500/10' : 'bg-surface-800'
              }`}
            >
              <div className="w-14 h-14 mx-auto mb-5 rounded-xl bg-red-500/10 flex items-center justify-center">
                <svg className="w-7 h-7 text-red-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}>
                  <path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z" strokeLinejoin="round"/>
                </svg>
              </div>

              <p className="text-xs uppercase tracking-wider text-gray-500 mb-2">bundle</p>

              {bundleFiles.length === 0 ? (
                <>
                  <p className="font-medium mb-1">drop your folder(s) here</p>
                  <p className="text-xs text-gray-600 mt-2">or multiple files, or both</p>
                </>
              ) : (
                <>
                  <p className="font-medium mb-1">
                    {bundleFiles.length} item{bundleFiles.length === 1 ? '' : 's'}
                  </p>
                  <p className="text-sm text-gray-500">{formatBytes(totalSize(bundleFiles))}</p>
                </>
              )}

              <div className="flex flex-wrap gap-2 justify-center mt-5">
                <label className="px-3 py-2 rounded-lg bg-surface-600 hover:bg-surface-500 text-sm cursor-pointer transition-colors">
                  select files
                  <input
                    type="file"
                    multiple
                    className="hidden"
                    onChange={(e) => addBundleFiles([...e.target.files])}
                  />
                </label>
                <label className="px-3 py-2 rounded-lg bg-surface-600 hover:bg-surface-500 text-sm cursor-pointer transition-colors">
                  select folder
                  <input
                    type="file"
                    multiple
                    webkitdirectory=""
                    className="hidden"
                    onChange={(e) => addBundleFiles([...e.target.files])}
                  />
                </label>
              </div>

              {bundleFiles.length > 0 && (
                <>
                  <input
                    type="text"
                    value={bundleName}
                    onChange={(e) => setBundleName(e.target.value)}
                    placeholder="bundle name"
                    className="mt-4 w-full px-3 py-2 bg-surface-700/50 border border-white/10 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:border-red-500/50"
                  />
                  <ul className="mt-3 space-y-1 max-h-40 overflow-y-auto text-left">
                    {bundleFiles.map((f, i) => (
                      <li
                        key={`${f.webkitRelativePath || f.name}-${i}`}
                        className="flex items-center gap-2 text-xs text-gray-500 group"
                      >
                        <span className="flex-1 truncate">{f.webkitRelativePath || f.name}</span>
                        <span className="text-gray-600 shrink-0">{formatBytes(f.size)}</span>
                        <button
                          onClick={() => removeBundleFile(i)}
                          aria-label={`remove ${f.webkitRelativePath || f.name}`}
                          title="remove this file"
                          className="shrink-0 w-5 h-5 rounded hover:bg-red-500/20 hover:text-red-400
                                     text-gray-600 transition-colors leading-none"
                        >
                          &times;
                        </button>
                      </li>
                    ))}
                  </ul>
                  {bundleFiles.length > 1 && (
                    <button
                      onClick={clearBundle}
                      className="mt-3 text-sm text-red-400 hover:text-red-300 transition-colors"
                    >
                      clear all
                    </button>
                  )}
                </>
              )}
            </div>
          </div>
        </div>

        {pending && (
          <div className="glass p-4 mb-6 border-red-500/20">
            <p className="text-sm text-red-400 mb-1">unfinished upload found</p>
            <p className="text-xs text-gray-500 mb-3">
              {pending.filename} was interrupted. {resuming
                ? 'now re-select the same file and upload to continue from where it stopped.'
                : 're-select the same file to resume from where it stopped.'}
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => { setPending(null); clearPendingUpload() }}
                className="px-3 py-1.5 rounded-lg bg-surface-600 text-xs transition-colors"
              >
                discard
              </button>
              <button
                onClick={() => setResuming(true)}
                className="px-3 py-1.5 rounded-lg bg-red-500 text-xs transition-colors"
              >
                resume
              </button>
            </div>
          </div>
        )}

        {(file || bundleFiles.length > 0) && (
          <div className="glass p-6 mb-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            <h3 className="text-sm font-medium text-gray-400 uppercase tracking-wider mb-4">options</h3>

            <div className="flex items-center justify-between p-4 rounded-xl bg-surface-700/30 border border-white/5 mb-4">
              <div>
                <p className="font-medium text-sm">compress</p>
                <p className="text-xs text-gray-500 mt-0.5">
                  {preparing
                    ? 'compressing to measure size...'
                    : prepared && useCompression && prepared.final !== prepared.raw
                      ? `${formatBytes(prepared.raw)} compresses to ${formatBytes(prepared.final)}`
                      : 'best for code, text, executables'}
                </p>
              </div>
              <button
                onClick={() => setUseCompression(!useCompression)}
                className={`relative w-11 h-6 rounded-full transition-colors duration-300 ${
                  useCompression ? 'bg-red-500' : 'bg-surface-600'
                }`}
              >
                <div className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform duration-300 ${
                  useCompression ? 'translate-x-5' : 'translate-x-0'
                }`} />
              </button>
            </div>


            <div className="grid sm:grid-cols-2 gap-4">
              <div className="flex items-center justify-between p-4 rounded-xl bg-surface-700/30 border border-white/5">
                <div>
                  <p className="font-medium text-sm flex items-center gap-1.5">
                    <svg className="w-3.5 h-3.5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round"
                            d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75M6 10.5h12v9.75H6z" />
                    </svg>
                    end to end encryption
                  </p>
                  <p className="text-xs text-gray-500 mt-0.5">key never leaves your browser</p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] uppercase tracking-wider text-gray-500">
                    always on
                  </span>
                  <button
                    onClick={() => setShowPolicy(true)}
                    aria-label="why encryption cannot be turned off"
                    className="relative w-11 h-6 rounded-full bg-red-500/70 cursor-pointer
                               transition-colors duration-300"
                  >
                    <div className="absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white
                                    shadow transition-transform duration-300 translate-x-5" />
                  </button>
                </div>
              </div>

              <div className="flex items-center justify-between p-4 rounded-xl bg-surface-700/30 border border-white/5">
                <div>
                  <p className="font-medium text-sm">download limit</p>
                  <p className="text-xs text-gray-500 mt-0.5">
                    {downloadMode === 'single' ? 'single use' : 'up to 10 downloads'}
                  </p>
                </div>
                <select
                  value={downloadMode}
                  onChange={(e) => setDownloadMode(e.target.value)}
                  className="bg-surface-600 border border-white/10 rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:border-red-500/50"
                >
                  <option value="single">single use</option>
                  <option value="multi">multi use</option>
                </select>
              </div>
            </div>

            <div className="mt-3">
              <ExpirySelector seconds={expirySeconds} onChange={setExpirySeconds} />
            </div>
          </div>
        )}

        {uploading && (
          <div className="glass p-6 mb-8">
            <UploadProgress stats={uploadStats} />
            <div className="text-center mt-4">
              <button
                onClick={() => {
                  if (abortRef.current) abortRef.current.abort()
                  clearPendingUpload()
                }}
                className="text-sm text-gray-500 hover:text-red-400 transition-colors"
              >
                cancel upload
              </button>
            </div>
          </div>
        )}

        {(file || bundleFiles.length > 0) && !uploading && (
          <div className="text-center mb-8">
            {rawSize > 0 && (
              <p className="text-xs text-gray-500 mb-3">
                {formatBytes(rawSize)} selected, limit {formatLimit(MAX_FILE_SIZE)}
                {prepared && useCompression && prepared.final !== rawSize && (
                  <> &middot; {formatBytes(prepared.final)} after compression</>
                )}
              </p>
            )}
            <div className="glass p-4 mb-4 max-w-md mx-auto">
              <input
                ref={honeypotRef}
                type="text"
                name="website"
                tabIndex={-1}
                autoComplete="off"
                aria-hidden="true"
                className="hidden"
              />
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={captchaVerified}
                  onChange={async (e) => {
                    const checked = e.target.checked
                    if (checked && !captchaToken) {
                      try {
                        const res = await fetch(`${import.meta.env.CB_API_URL || ''}/api/captcha/token`)
                        const data = await res.json()
                        setCaptchaToken(data.token)
                      } catch (err) {
                        setError('failed to load captcha')
                        return
                      }
                    }
                    setCaptchaVerified(checked)
                  }}
                  className="w-5 h-5 rounded border border-white/20 bg-surface-700 text-red-500 focus:ring-red-500/50"
                />
                <span className="text-sm text-gray-300">I am not a robot.</span>
              </label>
            </div>
            <button
              onClick={handleUpload}
              disabled={preparing || overLimit}
              className="btn-primary text-lg px-10 py-4"
            >
              {preparing ? 'preparing...' : overLimit ? 'over size limit' : useEncryption ? 'encrypt & upload' : 'upload file'}
            </button>
          </div>
        )}

        {error && (
          <div className="glass p-4 mb-8 border-red-500/20 bg-red-500/5">
            <p className="text-red-400 text-sm">{error}</p>
          </div>
        )}

        {result && (
          <div className="glass p-6 mb-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-xl bg-green-500/20 flex items-center justify-center">
                <svg className="w-5 h-5 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <div>
                <p className="font-medium">file uploaded successfully!</p>
                <p className="text-sm text-gray-500">
                  expires {expirySeconds >= DEFAULT_EXPIRY_SECONDS
                    ? 'in 24 hours (24 hours by default)'
                    : `in ${Math.floor(expirySeconds / 3600)}h ${Math.floor((expirySeconds % 3600) / 60)}m`}
                </p>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-surface-700/30 border border-white/5 mb-3">
              <p className="text-xs text-gray-500 mb-2">share this link:</p>
              <div className="flex items-center gap-2">
                <code className="flex-1 text-sm text-red-300 break-all font-mono">
                  {result.url}
                </code>
                <button
                  onClick={() => copyToClipboard('url', result.url)}
                  aria-label={copied === 'url' ? 'copied' : 'copy'}
                  className={copyBtnClass('url')}
                  >
                  {copied === 'url' ? (
                    <>
                      copied
                      <svg className="w-4 h-4 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                      </svg>
                    </>
                  ) : (
                    'copy'
                  )}
                </button>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-surface-700/30 border border-white/5 mb-3">
              <p className="text-xs text-gray-500 mb-2">file identifier</p>
              <div className="flex items-center gap-2">
                <code className="flex-1 text-sm text-red-300 break-all font-mono">
                  {result.token}
                </code>
                <button
                  onClick={() => copyToClipboard('token', result.token)}
                  aria-label={copied === 'token' ? 'copied' : 'copy'}
                  className={copyBtnClass('token')}
                  >
                  {copied === 'token' ? (
                    <>
                      copied
                      <svg className="w-4 h-4 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                      </svg>
                    </>
                  ) : (
                    'copy'
                  )}
                </button>
              </div>
            </div>

            {result.key && (
              <div className="p-4 rounded-xl bg-surface-700/30 border border-white/5 mb-4">
                <p className="text-xs text-gray-500 mb-2">decryption key</p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 text-sm text-red-300 break-all font-mono">
                    {result.key}
                  </code>
                  <button
                    onClick={() => copyToClipboard('key', result.key)}
                    aria-label={copied === 'key' ? 'copied' : 'copy'}
                    className={copyBtnClass('key')}
                    >
                    {copied === 'key' ? (
                    <>
                      copied
                      <svg className="w-4 h-4 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                      </svg>
                      </>
                    ) : (
                      'copy'
                    )}
                  </button>
                </div>
              </div>
            )}

            <div className="grid grid-cols-3 gap-4 text-center">
              <div>
                <p className="text-xs text-gray-500">size</p>
                <p className="text-sm font-medium">{formatBytes(result.size)}</p>
              </div>
              <div>
                <p className="text-xs text-gray-500">type</p>
                <p className="text-sm font-medium truncate">{result.fileType || '--'}</p>
              </div>
              <div>
                <p className="text-xs text-gray-500">expires</p>
                <p className="text-sm font-medium">{expiresLabel}</p>
              </div>
            </div>
          </div>
        )}

        {showPolicy && <EncryptionPolicyModal onClose={() => setShowPolicy(false)} />}

        <DownloadLookup />

        <div className="grid sm:grid-cols-3 gap-4 mt-16">
          {[
            {
              icon: (
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              ),
              title: 'zero knowledge',
              desc: 'files are encrypted in your browser. the server never sees your key.',
            },
            {
              icon: (
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              ),
              title: 'self destructing',
              desc: 'files automatically delete after 24 hours. no traces left behind.',
            },
            {
              icon: (
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              ),
              title: 'no signup',
              desc: 'no accounts, no email, no tracking. just upload and share.',
            },
          ].map((f, i) => (
            <div key={i} className="glass glass-hover p-6">
              <div className="w-10 h-10 rounded-xl bg-red-500/10 flex items-center justify-center text-red-500 mb-4">
                {f.icon}
              </div>
              <h3 className="font-medium mb-2">{f.title}</h3>
              <p className="text-sm text-gray-500">{f.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function formatBytes(bytes) {
  if (!bytes || bytes < 0) return '0 B'
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(0) + ' KB'
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB'
}

function formatDuration(ms) {
  if (!ms || ms < 0 || !isFinite(ms)) return '--'
  const total = Math.round(ms / 1000)
  if (total < 60) return total + 's'
  const m = Math.floor(total / 60)
  const s = total % 60
  if (m < 60) return s ? `${m}m ${s}s` : `${m}m`
  return `${Math.floor(m / 60)}h ${m % 60}m`
}

function UploadProgress({ stats }) {
  if (!stats) {
    return (
      <div>
        <div className="flex justify-between text-sm mb-2">
          <span className="text-gray-400">uploading...</span>
        </div>
        <div className="progress-bar">
          <div className="progress-fill w-1/4" />
        </div>
      </div>
    )
  }

  const compressing = stats.phase === 'compressing'

  const chunkLoaded = stats.chunkLoaded || 0
  const chunkTotal = stats.chunkTotal || 0
  const percent = chunkTotal
    ? Math.min(100, Math.round((chunkLoaded / chunkTotal) * 100))
    : 0

  return (
    <div>
      <div className="flex justify-between text-sm mb-2">
        <span className="text-gray-400">
          {compressing
            ? 'compressing'
            : `uploading chunk ${stats.chunkIndex + 1} of ${stats.totalParts}`}
        </span>
        <span className="text-red-400">{percent}%</span>
      </div>

      <div className="progress-bar">
        <div className="progress-fill" style={{ width: `${percent}%` }} />
      </div>

      <div className="flex flex-wrap justify-between gap-x-4 gap-y-1 mt-3 text-xs text-gray-500">
        <span>
          {compressing
            ? `${formatBytes(stats.loaded)} of ${formatBytes(stats.total)} processed`
            : `${formatBytes(chunkLoaded)} of ${formatBytes(chunkTotal)} in this chunk`}
        </span>
        {!compressing && stats.rate > 0 && <span>{formatBytes(stats.rate)}/s</span>}
        <span>{formatDuration(stats.elapsedMs)} elapsed</span>
        {!compressing && stats.etaMs != null && stats.etaMs > 0 && stats.loaded < stats.total && (
          <span>~{formatDuration(stats.etaMs)} left</span>
        )}
      </div>
    </div>
  )
}
