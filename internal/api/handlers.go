package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/allensuvorov/vuln-scan-query/internal/domain/entity"
)

// Service is the business logic interface
type Service interface {
	Scan(ctx context.Context, req entity.ScanRequest) error
	Query(ctx context.Context, req entity.QueryRequest) ([]entity.Vulnerability, error)
}

type Handler struct {
	svc Service
}

func New(svc Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) ScanHandler(w http.ResponseWriter, r *http.Request) {
	var req entity.ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	err := h.svc.Scan(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte("Scan started"))
}

func (h *Handler) QueryHandler(w http.ResponseWriter, r *http.Request) {
	var req entity.QueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	results, err := h.svc.Query(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}
