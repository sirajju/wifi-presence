// Package store is the SQLite persistence layer.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Device is a persisted record for a single MAC address.
type Device struct {
	MAC       string
	Label     string
	Owner     string
	Vendor    string
	Hostname  string // LAN name (NetBIOS/DHCP/DNS). Sticky — never overwritten with empty.
	LastIP    string
	FirstSeen time.Time
	LastSeen  time.Time
}

// Event is an append-only entry on the audit/alert feed.
type Event struct {
	ID      int64
	TS      time.Time
	MAC     string
	Kind    string
	Payload string
}

// Known event kinds. Keep this list tight — the wa-bot skill switches on them.
const (
	KindArrived       = "arrived"
	KindDeparted      = "departed"
	KindNewDevice     = "new_device"
	KindHouseEmpty    = "house_empty"
	KindHouseOccupied = "house_occupied"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("mkdir db dir: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // single-writer SQLite; keeps everything predictable and tiny.

	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA temp_store=MEMORY",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("%s: %w", pragma, err)
		}
	}

	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func migrate(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS devices (
            mac        TEXT PRIMARY KEY,
            label      TEXT NOT NULL DEFAULT '',
            owner      TEXT NOT NULL DEFAULT '',
            vendor     TEXT NOT NULL DEFAULT '',
            hostname   TEXT NOT NULL DEFAULT '',
            last_ip    TEXT NOT NULL DEFAULT '',
            first_seen INTEGER NOT NULL,
            last_seen  INTEGER NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS events (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            ts      INTEGER NOT NULL,
            mac     TEXT NOT NULL,
            kind    TEXT NOT NULL,
            payload TEXT NOT NULL DEFAULT ''
        )`,
		`CREATE INDEX IF NOT EXISTS events_ts ON events(ts)`,
		`CREATE INDEX IF NOT EXISTS devices_last_seen ON devices(last_seen)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	// Idempotent column add for DBs created before the hostname column existed.
	// SQLite doesn't support "ADD COLUMN IF NOT EXISTS", so swallow the dup error.
	if _, err := db.Exec(`ALTER TABLE devices ADD COLUMN hostname TEXT NOT NULL DEFAULT ''`); err != nil {
		if !strings.Contains(err.Error(), "duplicate column name") {
			return fmt.Errorf("migrate hostname column: %w", err)
		}
	}
	return nil
}

// UpsertSighting records that a MAC was seen at ts with ip/vendor/hostname.
// Returns (isNew, error). isNew is true when this MAC had never been seen.
//
// vendor and hostname are both "sticky": once a non-empty value has been
// recorded, it stays — a later blank reading never clobbers it. That's what
// lets us keep a hostname after the router reboots and loses its lease.
func (s *Store) UpsertSighting(ctx context.Context, mac, ip, vendor, hostname string, ts time.Time) (isNew bool, err error) {
	tsUnix := ts.Unix()
	var existed int
	err = s.db.QueryRowContext(ctx, `SELECT 1 FROM devices WHERE mac = ?`, mac).Scan(&existed)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = s.db.ExecContext(ctx, `
            INSERT INTO devices(mac, vendor, hostname, last_ip, first_seen, last_seen)
            VALUES(?, ?, ?, ?, ?, ?)
        `, mac, vendor, hostname, ip, tsUnix, tsUnix)
		return true, err
	case err != nil:
		return false, err
	}
	// Row exists — always update last_seen + last_ip, and fill vendor/hostname
	// only when we have a non-empty value and the existing one is empty.
	_, err = s.db.ExecContext(ctx, `
        UPDATE devices SET
            last_seen = ?,
            last_ip   = ?,
            vendor    = CASE WHEN vendor   = '' AND ? <> '' THEN ? ELSE vendor   END,
            hostname  = CASE WHEN hostname = '' AND ? <> '' THEN ? ELSE hostname END
        WHERE mac = ?
    `, tsUnix, ip, vendor, vendor, hostname, hostname, mac)
	return false, err
}

// SetLabel sets the label and (optionally) owner for a MAC. Owner "" leaves it untouched.
func (s *Store) SetLabel(ctx context.Context, mac, label, owner string) error {
	if owner == "" {
		_, err := s.db.ExecContext(ctx, `UPDATE devices SET label = ? WHERE mac = ?`, label, mac)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET label = ?, owner = ? WHERE mac = ?`, label, owner, mac)
	return err
}

// ListDevices returns every known device, most-recently-seen first.
func (s *Store) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT mac, label, owner, vendor, hostname, last_ip, first_seen, last_seen
        FROM devices ORDER BY last_seen DESC
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		var first, last int64
		if err := rows.Scan(&d.MAC, &d.Label, &d.Owner, &d.Vendor, &d.Hostname, &d.LastIP, &first, &last); err != nil {
			return nil, err
		}
		d.FirstSeen = time.Unix(first, 0)
		d.LastSeen = time.Unix(last, 0)
		out = append(out, d)
	}
	return out, rows.Err()
}

// AppendEvent persists an event. ID is populated on return.
func (s *Store) AppendEvent(ctx context.Context, e *Event) error {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO events(ts, mac, kind, payload) VALUES(?, ?, ?, ?)`,
		e.TS.Unix(), e.MAC, e.Kind, e.Payload)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	e.ID = id
	return nil
}

// EventsSince returns up to limit events with ts >= since, oldest first.
func (s *Store) EventsSince(ctx context.Context, since time.Time, limit int) ([]Event, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, ts, mac, kind, payload FROM events
        WHERE ts >= ? ORDER BY ts ASC, id ASC LIMIT ?
    `, since.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.MAC, &e.Kind, &e.Payload); err != nil {
			return nil, err
		}
		e.TS = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// TrimEvents deletes events older than retention. Returns number deleted.
func (s *Store) TrimEvents(ctx context.Context, retention time.Duration) (int64, error) {
	cutoff := time.Now().Add(-retention).Unix()
	res, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
