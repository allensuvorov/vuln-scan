package api

import (
	"net/http"
)

// Handler holds the dependencies for the HTTP layer.
// We'll inject the service layer later.
type Handler struct {
	// Service will be added here later
}

// NewHandler returns a new Handler instance.
// Useful for wiring everything together in main.go.
func NewHandler() *Handler {
	return &Handler{}
}

// POST /scan
func (h *Handler) ScanHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("scan endpoint not implemented yet"))
}

// POST /query
func (h *Handler) QueryHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("query endpoint not implemented yet"))
}
