package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"file2file/middleware"
	"file2file/models"
	"file2file/storage"
)

const multipartOverhead = 32 << 20
const maxFormFields = 16
const maxFieldBytes = 4096
const maxTotalParts = 512

var errPartTooLarge = errors.New("part too large")
var errPartIO = errors.New("part io error")

type UploadHandler struct {
	store         *storage.Store
	slots         chan struct{}
	quotaBytes    int64
	readTimeout   time.Duration
	writeTimeout  time.Duration
	maxFileBytes  int64
	maxChunkBytes int64
}

func NewUploadHandler(store *storage.Store, maxConcurrent int, quotaBytes int64, maxFileBytes int64, maxChunkBytes int64, readTimeout, writeTimeout time.Duration) *UploadHandler {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	if maxChunkBytes < 1 || maxChunkBytes > maxFileBytes {
		maxChunkBytes = maxFileBytes
	}
	return &UploadHandler{
		store:         store,
		slots:         make(chan struct{}, maxConcurrent),
		quotaBytes:    quotaBytes,
		readTimeout:   readTimeout,
		writeTimeout:  writeTimeout,
		maxFileBytes:  maxFileBytes,
		maxChunkBytes: maxChunkBytes,
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (h *UploadHandler) Handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.ContentLength > h.maxFileBytes+multipartOverhead {
		http.Error(w, "file exceeds size limit", http.StatusRequestEntityTooLarge)
		return
	}

	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	case <-r.Context().Done():
		http.Error(w, "request cancelled", http.StatusRequestTimeout)
		return
	case <-time.After(30 * time.Second):
		http.Error(w, "server busy, retry shortly", http.StatusServiceUnavailable)
		return
	}

	rc := http.NewResponseController(w)
	rc.SetReadDeadline(time.Now().Add(h.readTimeout))
	rc.SetWriteDeadline(time.Now().Add(h.writeTimeout))

	r.Body = http.MaxBytesReader(w, r.Body, h.maxFileBytes+multipartOverhead)

	fields := make(map[string]string)
	var part *multipart.Part
	var filename string

	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "malformed upload", http.StatusBadRequest)
		return
	}

	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "malformed upload", http.StatusBadRequest)
			return
		}

		if p.FileName() != "" {
			part = p
			filename = p.FileName()
			break
		}

		if len(fields) < maxFormFields {
			value, _ := io.ReadAll(io.LimitReader(p, maxFieldBytes))
			fields[p.FormName()] = string(value)
		}
		p.Close()
	}

	if part == nil {
		http.Error(w, "no file provided", http.StatusBadRequest)
		return
	}
	defer part.Close()

	// storing plaintext would break the zero server knowledge guarantee, so it is
	// refused here rather than merely avoided by the official client.
	// only the opening part carries the flag; later parts of a chunked upload are
	// checked against the session that the first part already created.
	if fields["upload_id"] == "" {
		if fields["encrypted"] != "true" {
			http.Error(w, "encryption is required", http.StatusBadRequest)
			return
		}
	} else if session, err := h.store.LoadSession(fields["upload_id"]); err != nil || !session.Encrypted {
		http.Error(w, "encryption is required", http.StatusBadRequest)
		return
	}

	if _, ok := fields["part_index"]; ok {
		h.handleChunk(w, r, fields, part, filename)
		return
	}

	h.handleSingle(w, r, fields, part, filename)
}

func writePart(part io.Reader, destPath string, limit int64) (int64, []byte, error) {
	tmpPath := destPath + ".tmp"
	os.Remove(tmpPath)

	dest, err := os.Create(tmpPath)
	if err != nil {
		return 0, nil, errPartIO
	}
	defer dest.Close()

	head := make([]byte, 512)
	headN, readErr := io.ReadFull(part, head)
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		os.Remove(tmpPath)
		return 0, nil, errPartIO
	}

	var written int64
	if headN > 0 {
		n, werr := dest.Write(head[:headN])
		written = int64(n)
		if werr != nil {
			os.Remove(tmpPath)
			return 0, nil, errPartIO
		}
	}

	rest, copyErr := io.Copy(dest, io.LimitReader(part, limit+1-written))
	written += rest
	if copyErr != nil {
		os.Remove(tmpPath)
		return 0, nil, errPartIO
	}
	if written > limit {
		os.Remove(tmpPath)
		return 0, nil, errPartTooLarge
	}

	if err := dest.Sync(); err != nil {
		os.Remove(tmpPath)
		return 0, nil, errPartIO
	}
	dest.Close()

	if err := os.Rename(tmpPath, destPath); err != nil {
		os.Remove(tmpPath)
		return 0, nil, errPartIO
	}

	return written, head[:headN], nil
}

func writeChunkError(w http.ResponseWriter, err error) {
	if errors.Is(err, errPartTooLarge) {
		http.Error(w, "chunk exceeds size limit", http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, "upload failed", http.StatusInternalServerError)
}

const (
	defaultExpiry = 24 * time.Hour
	minExpiry     = time.Minute
	maxExpiry     = 24 * time.Hour
)

// the client only ever gets to ask; the server decides
func expiryFrom(fields map[string]string) time.Duration {
	secs, err := strconv.ParseInt(fields["expires_in"], 10, 64)
	if err != nil || secs <= 0 {
		return defaultExpiry
	}
	d := time.Duration(secs) * time.Second
	if d < minExpiry {
		return minExpiry
	}
	if d > maxExpiry {
		return maxExpiry
	}
	return d
}

// sessions written before custom expiry existed carry no value, so they keep 24h
func sessionExpiry(session models.UploadSession) time.Duration {
	if session.ExpiresIn <= 0 {
		return defaultExpiry
	}
	d := time.Duration(session.ExpiresIn) * time.Second
	if d < minExpiry {
		return minExpiry
	}
	if d > maxExpiry {
		return maxExpiry
	}
	return d
}

func maxDownloadsFrom(fields map[string]string) int {
	if fields["downloads"] == "multi" {
		return 10
	}
	return 1
}

func headBytes(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	head := make([]byte, 512)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil
	}
	return head[:n]
}

func (h *UploadHandler) handleSingle(w http.ResponseWriter, r *http.Request, fields map[string]string, part *multipart.Part, filename string) {
	if !middleware.ValidateUploadFields(w, fields) {
		return
	}

	ip := middleware.ClientIP(r)
	estimate := r.ContentLength
	if estimate <= 0 || estimate > h.maxFileBytes {
		estimate = h.maxFileBytes
	}

	if !middleware.AllowQuota(ip, estimate, h.quotaBytes) {
		http.Error(w, "daily upload quota exceeded", http.StatusTooManyRequests)
		return
	}
	if !h.store.HasSpace(estimate) {
		http.Error(w, "storage full", http.StatusInsufficientStorage)
		return
	}

	token := randomHex(16)
	storedName := token + ".bin"
	destPath := filepath.Join(h.store.GetUploadDir(), storedName)

	written, head, err := writePart(part, destPath, h.maxFileBytes)
	if err != nil {
		writeChunkError(w, err)
		return
	}

	if written <= 0 {
		os.Remove(destPath)
		http.Error(w, "empty file", http.StatusBadRequest)
		return
	}

	fileType := storage.DetectFileType(head)
	encrypted := fields["encrypted"] == "true"

	meta := models.FileMetadata{
		Token:        token,
		StoredName:   storedName,
		OriginalHash: storage.HashFilename(filename),
		Size:         written,
		FileType:     fileType,
		ExpiresAt:    time.Now().Add(expiryFrom(fields)),
		MaxDownloads: maxDownloadsFrom(fields),
		Encrypted:    encrypted,
		CreatedAt:    time.Now(),
	}
	if !encrypted {
		meta.OriginalName = storage.SanitizeFilename(filename)
	}

	if err := h.store.Save(token, meta); err != nil {
		os.Remove(destPath)
		http.Error(w, "metadata error", http.StatusInternalServerError)
		return
	}

	h.store.AddUsage(written)
	middleware.ConsumeQuota(ip, written)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":     token,
		"expires":   meta.ExpiresAt.Format(time.RFC3339),
		"size":      written,
		"file_type": fileType,
		"done":      true,
	})
}

func (h *UploadHandler) handleChunk(w http.ResponseWriter, r *http.Request, fields map[string]string, part *multipart.Part, filename string) {
	partIndex, err1 := strconv.Atoi(fields["part_index"])
	totalParts, err2 := strconv.Atoi(fields["total_parts"])
	totalSize, err3 := strconv.ParseInt(fields["total_size"], 10, 64)
	uploadID := fields["upload_id"]

	if err1 != nil || err2 != nil || err3 != nil {
		http.Error(w, "invalid chunk metadata", http.StatusBadRequest)
		return
	}
	if partIndex < 0 || totalParts < 1 || totalParts > maxTotalParts || partIndex >= totalParts {
		http.Error(w, "invalid chunk metadata", http.StatusBadRequest)
		return
	}
	if totalSize <= 0 || totalSize > h.maxFileBytes {
		http.Error(w, "file exceeds size limit", http.StatusRequestEntityTooLarge)
		return
	}

	var session models.UploadSession

	if partIndex == 0 {
		if !middleware.ValidateUploadFields(w, fields) {
			return
		}

		ip := middleware.ClientIP(r)
		if !middleware.AllowQuota(ip, totalSize, h.quotaBytes) {
			http.Error(w, "daily upload quota exceeded", http.StatusTooManyRequests)
			return
		}
		middleware.ConsumeQuota(ip, totalSize)
		if !h.store.HasSpaceForStaging(totalSize) {
			middleware.ConsumeQuota(ip, -totalSize)
			http.Error(w, "storage full", http.StatusInsufficientStorage)
			return
		}

		if uploadID == "" || !storage.ValidToken(uploadID) {
			uploadID = randomHex(16)
		}

		token := randomHex(16)
		sourceName := fields["filename"]
		if sourceName == "" {
			sourceName = filename
		}
		session = models.UploadSession{
			UploadID:     uploadID,
			Token:        token,
			TotalParts:   totalParts,
			TotalSize:    totalSize,
			StoredName:   token + ".bin",
			Filename:     sourceName,
			Encrypted:    fields["encrypted"] == "true",
			MaxDownloads: maxDownloadsFrom(fields),
			ExpiresIn:    int64(expiryFrom(fields) / time.Second),
			IP:           ip,
			CreatedAt:    time.Now(),
		}
		if err := h.store.SaveSession(session); err != nil {
			http.Error(w, "storage error", http.StatusInternalServerError)
			return
		}
	} else {
		if uploadID == "" || !storage.ValidToken(uploadID) {
			http.Error(w, "upload id required", http.StatusBadRequest)
			return
		}
		loaded, err := h.store.LoadSession(uploadID)
		if err != nil {
			http.Error(w, "unknown upload session", http.StatusBadRequest)
			return
		}
		session = *loaded
		if session.TotalParts != totalParts || session.TotalSize != totalSize {
			http.Error(w, "chunk does not match session", http.StatusBadRequest)
			return
		}
	}

	stagedBefore := h.store.SessionStagedBytes(session.UploadID, session.TotalParts)
	if stagedBefore >= session.TotalSize {
		http.Error(w, "upload exceeds declared size", http.StatusBadRequest)
		return
	}
	if !h.store.HasSpaceForStaging(session.TotalSize - stagedBefore) {
		http.Error(w, "storage full", http.StatusInsufficientStorage)
		return
	}

	partPath := h.store.PartPath(session.UploadID, partIndex)
	previous := int64(0)
	if info, statErr := os.Stat(partPath); statErr == nil {
		previous = info.Size()
	}

	written, _, err := writePart(part, partPath, h.maxChunkBytes)
	if err != nil {
		writeChunkError(w, err)
		return
	}

	h.store.AddStaging(written - previous)

	stagedAfter := h.store.SessionStagedBytes(session.UploadID, session.TotalParts)
	if stagedAfter > session.TotalSize {
		os.Remove(partPath)
		h.store.AddStaging(-written)
		http.Error(w, "upload exceeds declared size", http.StatusBadRequest)
		return
	}

	received := h.store.ReceivedParts(session.UploadID, session.TotalParts)
	if len(received) < session.TotalParts {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"upload_id": session.UploadID,
			"token":     session.Token,
			"received":  received,
			"total":     session.TotalParts,
			"done":      false,
		})
		return
	}

	destPath := filepath.Join(h.store.GetUploadDir(), session.StoredName)
	dest, err := os.Create(destPath)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	var assembled int64
	for i := 0; i < session.TotalParts; i++ {
		p, err := os.Open(h.store.PartPath(session.UploadID, i))
		if err != nil {
			dest.Close()
			os.Remove(destPath)
			http.Error(w, "assembly failed", http.StatusInternalServerError)
			return
		}
		n, err := io.Copy(dest, p)
		p.Close()
		if err != nil {
			dest.Close()
			os.Remove(destPath)
			http.Error(w, "assembly failed", http.StatusInternalServerError)
			return
		}
		assembled += n
	}
	dest.Close()

	if assembled != session.TotalSize {
		os.Remove(destPath)
		h.store.DropSession(session)
		h.store.ReleaseStaging(assembled)
		middleware.ConsumeQuota(session.IP, -session.TotalSize)
		http.Error(w, "size mismatch, restart upload", http.StatusBadRequest)
		return
	}

	fileType := storage.DetectFileType(headBytes(destPath))
	meta := models.FileMetadata{
		Token:        session.Token,
		StoredName:   session.StoredName,
		OriginalHash: storage.HashFilename(session.Filename),
		Size:         assembled,
		FileType:     fileType,
		ExpiresAt:    time.Now().Add(sessionExpiry(session)),
		MaxDownloads: session.MaxDownloads,
		Encrypted:    session.Encrypted,
		CreatedAt:    time.Now(),
	}
	if !session.Encrypted {
		meta.OriginalName = storage.SanitizeFilename(session.Filename)
	}

	if err := h.store.Save(session.Token, meta); err != nil {
		os.Remove(destPath)
		http.Error(w, "metadata error", http.StatusInternalServerError)
		return
	}

	h.store.DropSession(session)
	h.store.ReleaseStaging(assembled)
	h.store.AddUsage(assembled)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":     session.Token,
		"expires":   meta.ExpiresAt.Format(time.RFC3339),
		"size":      assembled,
		"file_type": fileType,
		"done":      true,
	})
}

func (h *UploadHandler) GetStore() *storage.Store {
	return h.store
}
