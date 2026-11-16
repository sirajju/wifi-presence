// Package state tracks per-MAC presence with debounce windows and emits
// transition events into the store.
package state

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/sirajju/wifi-presence/internal/scanner"
	"github.com/sirajju/wifi-presence/internal/store"
)

// Presence is the public view of what the Machine knows about a device.
type Presence struct {
	MAC      string
	Label    string
	Owner    string
	Vendor   string
	LastIP   string
	LastSeen time.Time
	Home     bool
}

type Snapshot struct {
	LastScan time.Time
	Home     []Presence
	Away     []Presence
}

type Machine struct {
	st         *store.Store
	homeWin    time.Duration
	awayWin    time.Duration
	log        zerolog.Logger

	mu       sync.RWMutex
	lastSeen map[string]time.Time
	homeFlag map[string]bool // last published status (to detect transitions)
	lastScan time.Time
	occupied bool
}

func New(st *store.Store, homeWindow, awayWindow time.Duration, log zerolog.Logger) *Machine {
	return &Machine{
		st:       st,
		homeWin:  homeWindow,
		awayWin:  awayWindow,
		log:      log.With().Str("component", "state").Logger(),
		lastSeen: make(map[string]time.Time),
		homeFlag: make(map[string]bool),
	}
}

// Rehydrate pulls last_seen timestamps from persisted devices so a restart
// doesn't re-fire "arrived" events for devices already home.
func (m *Machine) Rehydrate(ctx context.Context) error {
	devices, err := m.st.ListDevices(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	anyHome := false
	for _, d := range devices {
		m.lastSeen[d.MAC] = d.LastSeen
		home := now.Sub(d.LastSeen) <= m.homeWin
		m.homeFlag[d.MAC] = home
		if home {
			anyHome = true
		}
	}
	m.occupied = anyHome
	return nil
}

// Observe records a batch of sightings, updates state, and emits events for any
// transitions. Returns the events that were persisted this cycle.
func (m *Machine) Observe(ctx context.Context, sightings []scanner.Sighting) []store.Event {
	now := time.Now()

	var newDevices []scanner.Sighting
	for _, s := range sightings {
		isNew, err := m.st.UpsertSighting(ctx, s.MAC, s.IP, s.Vendor, s.TS)
		if err != nil {
			m.log.Error().Err(err).Str("mac", s.MAC).Msg("upsert")
			continue
		}
		if isNew {
			newDevices = append(newDevices, s)
		}
	}

	m.mu.Lock()
	for _, s := range sightings {
		m.lastSeen[s.MAC] = s.TS
	}
	m.lastScan = now

	// Compute transitions.
	transitions := map[string]bool{} // mac -> newHome
	anyHome := false
	for mac, ts := range m.lastSeen {
		age := now.Sub(ts)
		var home bool
		switch {
		case age <= m.homeWin:
			home = true
		case age >= m.awayWin:
			home = false
		default:
			// Within the hysteresis gap — keep whatever we last published.
			home = m.homeFlag[mac]
		}
		prev, had := m.homeFlag[mac]
		if !had || prev != home {
			transitions[mac] = home
			m.homeFlag[mac] = home
		}
		if home {
			anyHome = true
		}
	}
	wasOccupied := m.occupied
	m.occupied = anyHome
	m.mu.Unlock()

	// Persist events (outside the lock).
	var out []store.Event
	for _, s := range newDevices {
		ev := store.Event{TS: now, MAC: s.MAC, Kind: store.KindNewDevice, Payload: s.Vendor}
		if err := m.st.AppendEvent(ctx, &ev); err != nil {
			m.log.Error().Err(err).Msg("append new_device")
			continue
		}
		out = append(out, ev)
	}
	for mac, home := range transitions {
		kind := store.KindDeparted
		if home {
			kind = store.KindArrived
		}
		ev := store.Event{TS: now, MAC: mac, Kind: kind}
		if err := m.st.AppendEvent(ctx, &ev); err != nil {
			m.log.Error().Err(err).Msg("append transition")
			continue
		}
		out = append(out, ev)
	}
	if wasOccupied != anyHome {
		kind := store.KindHouseEmpty
		if anyHome {
			kind = store.KindHouseOccupied
		}
		ev := store.Event{TS: now, Kind: kind}
		if err := m.st.AppendEvent(ctx, &ev); err != nil {
			m.log.Error().Err(err).Msg("append house state")
		} else {
			out = append(out, ev)
		}
	}
	return out
}

// Snapshot returns the current home/away view, built from the store + the
// in-memory lastSeen map so the API can serve it without touching disk again
// if nothing changed.
func (m *Machine) Snapshot(ctx context.Context) (Snapshot, error) {
	devices, err := m.st.ListDevices(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	var home, away []Presence
	for _, d := range devices {
		ls := d.LastSeen
		if t, ok := m.lastSeen[d.MAC]; ok && t.After(ls) {
			ls = t
		}
		p := Presence{
			MAC:      d.MAC,
			Label:    d.Label,
			Owner:    d.Owner,
			Vendor:   d.Vendor,
			LastIP:   d.LastIP,
			LastSeen: ls,
			Home:     m.homeFlag[d.MAC],
		}
		if p.Home {
			home = append(home, p)
		} else {
			away = append(away, p)
		}
	}
	sort.Slice(home, func(i, j int) bool { return home[i].LastSeen.After(home[j].LastSeen) })
	sort.Slice(away, func(i, j int) bool { return away[i].LastSeen.After(away[j].LastSeen) })
	return Snapshot{LastScan: m.lastScan, Home: home, Away: away}, nil
}
