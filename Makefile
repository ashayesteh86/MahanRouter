VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build rozaneh web test lab cross clean

# The web panel is built into internal/panel/dist and embedded in mahan-agent.
# The built files are committed, so `make build` works without Node.
web:
	cd web && npm ci --no-audit --no-fund && npm run build

# Rozaneh (our own VPN) is built from its own repository next to this one.
ROZANEH_SRC ?= ../mahan-vpn

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/ ./cmd/...

rozaneh:
	cd $(ROZANEH_SRC) && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $(CURDIR)/bin/rozaneh ./cmd/rozaneh

test:
	go vet ./...
	go test ./...

# End-to-end test in network namespaces (root).
lab: build
	sudo ./tests/lab/run.sh

# Static binaries for the targets in the architecture doc.
cross:
	for arch in amd64 arm64 arm mips mipsle; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -ldflags "$(LDFLAGS)" -o dist/$$arch/ ./cmd/... ; \
	done

clean:
	rm -rf bin dist
