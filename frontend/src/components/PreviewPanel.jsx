import { usePreview } from './usePreview'
import { formatBytes } from '../lib/format'

export default function PreviewPanel({ hook, onClose, label }) {
  const { preview, loading, error, clear, ready, activate } = hook

  const close = () => {
    clear()
    onClose()
  }

  return (
    <div role="dialog" aria-label="file preview"
         className="mb-6 rounded-2xl bg-surface-800 border border-white/10 overflow-hidden">
      <div className="flex flex-col">
        <div className="flex items-center justify-between gap-3 px-5 py-3 border-b border-white/5">
          <div className="min-w-0">
            <p className="font-medium text-sm truncate">{preview?.name || label || 'preview'}</p>
            {preview ? (
              <p className="text-xs text-gray-500">
                {formatBytes(preview.size)} &middot; decrypted in your browser
              </p>
            ) : (
              <p className="text-xs text-gray-500">nothing downloaded yet</p>
            )}
          </div>
          <button onClick={close} aria-label="close preview"
                  className="w-8 h-8 rounded-lg hover:bg-surface-700 text-gray-400
                             hover:text-red-400 transition-colors text-lg leading-none">
            &times;
          </button>
        </div>

        <div className="p-5 overflow-auto min-h-[160px] max-h-[50vh]">
          {!loading && !error && !preview && (
            <div className="h-full flex flex-col items-center justify-center gap-3 text-center">
              <p className="text-sm text-gray-400">
                preview decrypts and renders this file in your browser
              </p>
              <button
                onClick={activate}
                disabled={!ready}
                className="px-4 py-2 rounded-xl bg-red-500 hover:bg-red-600 text-sm
                           font-medium transition-colors disabled:opacity-40"
              >
                load preview
              </button>
            </div>
          )}
          {loading && (
            <div className="h-full flex items-center justify-center text-gray-400 text-sm">
              decrypting preview...
            </div>
          )}
          {!loading && error && (
            <div className="h-full flex items-center justify-center text-gray-400 text-sm text-center">
              {error}
            </div>
          )}
          {!loading && !error && preview?.kind === 'text' && (
            <pre className="text-xs font-mono whitespace-pre-wrap break-words
                            bg-black/30 rounded-lg p-4 max-h-[45vh] overflow-auto">
              {preview.text}
            </pre>
          )}
          {!loading && !error && preview?.kind === 'image' && (
            <img src={preview.url} alt={preview.name}
                 className="max-h-[45vh] mx-auto rounded-lg" />
          )}
          {!loading && !error && preview?.kind === 'pdf' && (
            <iframe src={preview.url} title={preview.name}
                    className="w-full h-[55vh] rounded-lg bg-white" />
          )}
          {!loading && !error && preview?.kind === 'audio' && (
            <audio src={preview.url} controls className="w-full" />
          )}
          {!loading && !error && preview?.kind === 'video' && (
            <video src={preview.url} controls className="max-h-[45vh] w-full rounded-lg" />
          )}
        </div>
      </div>
    </div>
  )
}