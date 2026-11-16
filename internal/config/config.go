// Package config loads runtime settings from environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Listen               string
	Interface            string
	Subnet               string
	DBPath               string
	PollInterval         time.Duration
	HomeWindow           time.Duration
	AwayWindow           time.Duration
	EventRetentionDays   int
	LogLevel             string
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	c := &Config{
		Listen:             env("PRESENCE_LISTEN", "127.0.0.1:8765"),
		Interface:          env("PRESENCE_INTERFACE", "auto"),
		Subnet:             env("PRESENCE_SUBNET", "auto"),
		DBPath:             env("PRESENCE_DB", "./data/presence.db"),
		PollInterval:       envDuration("PRESENCE_POLL_INTERVAL", 30*time.Second),
		HomeWindow:         envDuration("PRESENCE_HOME_WINDOW", 90*time.Second),
		AwayWindow:         envDuration("PRESENCE_AWAY_WINDOW", 5*time.Minute),
		EventRetentionDays: envInt("PRESENCE_EVENT_RETENTION_DAYS", 30),
		LogLevel:           env("PRESENCE_LOG_LEVEL", "info"),
	}

	if c.HomeWindow >= c.AwayWindow {
		return nil, fmt.Errorf("PRESENCE_HOME_WINDOW (%s) must be less than PRESENCE_AWAY_WINDOW (%s)", c.HomeWindow, c.AwayWindow)
	}
	return c, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
