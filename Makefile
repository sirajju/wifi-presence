BINARY := presence
BIN_DIR := bin
GOFLAGS := -trimpath -ldflags="-s -w"
GO ?= go

.PHONY: build build-linux run tidy clean fmt vet test install-systemd

build:
	mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -o $(BIN_DIR)/$(BINARY) ./cmd/presence

# Static Linux amd64 build (no cgo thanks to modernc.org/sqlite).
build-linux:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BIN_DIR)/$(BINARY)-linux-amd64 ./cmd/presence

run:
	$(GO) run ./cmd/presence

tidy:
	$(GO) mod tidy

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

clean:
	rm -rf $(BIN_DIR) dist

# Install the binary + systemd unit for the current user. No root needed.
install-systemd: build-linux
	install -D -m 0755 $(BIN_DIR)/$(BINARY)-linux-amd64 $(HOME)/.local/bin/$(BINARY)
	install -D -m 0644 scripts/presence.service $(HOME)/.config/systemd/user/presence.service
	systemctl --user daemon-reload
	@echo "Enable with:  systemctl --user enable --now presence"
