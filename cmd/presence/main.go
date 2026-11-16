// Command presence is a tiny daemon that tracks who is on the LAN by MAC,
// labels them, and exposes a local HTTP API for the wa-bot "presence" skill.
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/sirajju/wifi-presence/internal/api"
	"github.com/sirajju/wifi-presence/internal/config"
	"github.com/sirajju/wifi-presence/internal/scanner"
	"github.com/sirajju/wifi-presence/internal/state"
	"github.com/sirajju/wifi-presence/internal/store"
)

func main() {
	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		With().Timestamp().Logger()

	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("config")
	}
	if lvl, err := zerolog.ParseLevel(cfg.LogLevel); err == nil {
		log = log.Level(lvl)
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatal().Err(err).Str("path", cfg.DBPath).Msg("open store")
	}
	defer st.Close()

	sc, err := scanner.New(cfg.Interface, cfg.Subnet, log)
	if err != nil {
		log.Fatal().Err(err).Msg("scanner")
	}
	log.Info().Str("iface", sc.InterfaceName()).Str("subnet", sc.Subnet()).Msg("scanner ready")

	sm := state.New(st, cfg.HomeWindow, cfg.AwayWindow, log)
	if err := sm.Rehydrate(context.Background()); err != nil {
		log.Warn().Err(err).Msg("rehydrate (continuing with empty state)")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Scan loop — the only heavy work. Runs in its own goroutine.
	go runScanner(ctx, sc, sm, cfg.PollInterval, log)

	// Event retention trim, once per day.
	go runRetention(ctx, st, cfg.EventRetentionDays, log)

	srv := api.New(st, sm, log)
	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Info().Str("addr", cfg.Listen).Msg("api listening")
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Msg("http")
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Info().Msg("shutting down")
	shutdownCtx, cancelShut := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShut()
	_ = httpSrv.Shutdown(shutdownCtx)
	cancel()
}

func runScanner(ctx context.Context, sc *scanner.Scanner, sm *state.Machine, interval time.Duration, log zerolog.Logger) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	// Kick off immediately so the API has something to serve on first request.
	scanOnce(ctx, sc, sm, log)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			scanOnce(ctx, sc, sm, log)
		}
	}
}

func scanOnce(ctx context.Context, sc *scanner.Scanner, sm *state.Machine, log zerolog.Logger) {
	start := time.Now()
	sightings, err := sc.Scan(ctx)
	if err != nil {
		log.Error().Err(err).Msg("scan")
		return
	}
	events := sm.Observe(ctx, sightings)
	log.Debug().
		Int("sightings", len(sightings)).
		Int("events", len(events)).
		Dur("took", time.Since(start)).
		Msg("scan complete")
}

func runRetention(ctx context.Context, st *store.Store, days int, log zerolog.Logger) {
	if days <= 0 {
		return
	}
	tick := time.NewTicker(24 * time.Hour)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			n, err := st.TrimEvents(ctx, time.Duration(days)*24*time.Hour)
			if err != nil {
				log.Warn().Err(err).Msg("trim events")
				continue
			}
			if n > 0 {
				log.Info().Int64("deleted", n).Msg("retention trim")
			}
		}
	}
}
