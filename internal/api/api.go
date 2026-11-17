// Package api serves the local HTTP interface consumed by the wa-bot skill.
package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/sirajju/wifi-presence/internal/state"
	"github.com/sirajju/wifi-presence/internal/store"
)

type Server struct {
	st  *store.Store
	sm  *state.Machine
	log zerolog.Logger
	mux *http.ServeMux
}

func New(st *store.Store, sm *state.Machine, log zerolog.Logger) *Server {
	s := &Server{st: st, sm: sm, log: log.With().Str("component", "api").Logger()}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /api/status", s.status)
	mux.HandleFunc("GET /api/devices", s.devices)
	mux.HandleFunc("GET /api/events", s.events)
	mux.HandleFunc("POST /api/label", s.label)
	s.mux = mux
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// --- Handlers --------------------------------------------------------------

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type statusResp struct {
	LastScan string          `json:"last_scan"`
	Home     []presenceJSON  `json:"home"`
	Away     []presenceJSON  `json:"away"`
	Counts   map[string]int  `json:"counts"`
}

type presenceJSON struct {
	MAC      string `json:"mac"`
	Label    string `json:"label"`
	Owner    string `json:"owner"`
	Vendor   string `json:"vendor"`
	Hostname string `json:"hostname"`
	LastIP   string `json:"last_ip"`
	LastSeen string `json:"last_seen"`
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	snap, err := s.sm.Snapshot(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	resp := statusResp{
		LastScan: tsOrEmpty(snap.LastScan),
		Home:     make([]presenceJSON, 0, len(snap.Home)),
		Away:     make([]presenceJSON, 0, len(snap.Away)),
		Counts:   map[string]int{"home": len(snap.Home), "away": len(snap.Away)},
	}
	for _, p := range snap.Home {
		resp.Home = append(resp.Home, toJSON(p))
	}
	for _, p := range snap.Away {
		resp.Away = append(resp.Away, toJSON(p))
	}
	writeJSON(w, http.StatusOK, resp)
}

type deviceJSON struct {
	MAC       string `json:"mac"`
	Label     string `json:"label"`
	Owner     string `json:"owner"`
	Vendor    string `json:"vendor"`
	Hostname  string `json:"hostname"`
	LastIP    string `json:"last_ip"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Home      bool   `json:"home"`
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	snap, err := s.sm.Snapshot(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	// Build a lookup of first_seen from the store.
	devs, err := s.st.ListDevices(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	homeByMac := make(map[string]bool, len(snap.Home)+len(snap.Away))
	for _, p := range snap.Home {
		homeByMac[p.MAC] = true
	}
	out := make([]deviceJSON, 0, len(devs))
	for _, d := range devs {
		out = append(out, deviceJSON{
			MAC:       d.MAC,
			Label:     d.Label,
			Owner:     d.Owner,
			Vendor:    d.Vendor,
			Hostname:  d.Hostname,
			LastIP:    d.LastIP,
			FirstSeen: tsOrEmpty(d.FirstSeen),
			LastSeen:  tsOrEmpty(d.LastSeen),
			Home:      homeByMac[d.MAC],
		})
	}
	writeJSON(w, http.StatusOK, out)
}

type eventJSON struct {
	ID      int64  `json:"id"`
	TS      string `json:"ts"`
	MAC     string `json:"mac"`
	Kind    string `json:"kind"`
	Payload string `json:"payload"`
	Label   string `json:"label,omitempty"`
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since := time.Unix(0, 0)
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			since = t
		} else if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			since = time.Unix(n, 0)
		} else {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("since must be RFC3339 or unix seconds"))
			return
		}
	}
	limit := 100
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	evs, err := s.st.EventsSince(r.Context(), since, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	// Enrich with labels so the bot doesn't have to do a second call.
	devs, _ := s.st.ListDevices(r.Context())
	labelByMac := make(map[string]string, len(devs))
	for _, d := range devs {
		if d.Label != "" {
			labelByMac[d.MAC] = d.Label
		} else if d.Owner != "" {
			labelByMac[d.MAC] = d.Owner
		}
	}
	out := make([]eventJSON, 0, len(evs))
	for _, e := range evs {
		out = append(out, eventJSON{
			ID:      e.ID,
			TS:      tsOrEmpty(e.TS),
			MAC:     e.MAC,
			Kind:    e.Kind,
			Payload: e.Payload,
			Label:   labelByMac[e.MAC],
		})
	}
	writeJSON(w, http.StatusOK, out)
}

type labelReq struct {
	MAC   string `json:"mac"`
	Label string `json:"label"`
	Owner string `json:"owner"`
}

var macRegex = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

func (s *Server) label(w http.ResponseWriter, r *http.Request) {
	var req labelReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	req.MAC = normalizeMAC(req.MAC)
	if !macRegex.MatchString(req.MAC) {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid mac"))
		return
	}
	if req.Label == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("label required"))
		return
	}
	if err := s.st.SetLabel(r.Context(), req.MAC, req.Label, req.Owner); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- Helpers ---------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func tsOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func toJSON(p state.Presence) presenceJSON {
	return presenceJSON{
		MAC:      p.MAC,
		Label:    p.Label,
		Owner:    p.Owner,
		Vendor:   p.Vendor,
		Hostname: p.Hostname,
		LastIP:   p.LastIP,
		LastSeen: tsOrEmpty(p.LastSeen),
	}
}

func normalizeMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", ":")
	// Guard against split-with-dots form ("aabb.ccdd.eeff"); unlikely, but cheap to support.
	if strings.Count(s, ".") == 2 && len(s) == 14 {
		parts := strings.Split(s, ".")
		if len(parts) == 3 {
			s = parts[0][:2] + ":" + parts[0][2:] + ":" +
				parts[1][:2] + ":" + parts[1][2:] + ":" +
				parts[2][:2] + ":" + parts[2][2:]
		}
	}
	return s
}

// Unused but keeps net imported for potential future client-ip logging.
var _ = net.IP{}
