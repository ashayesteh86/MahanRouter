VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build rozaneh sing-box web test lab cross clean

# The web panel is built into internal/panel/dist and embedded in mahan-agent.
# The built files are committed, so `make build` works without Node.
web:
	cd web && npm ci --no-audit --no-fund && npm run build

# Rozaneh (our own VPN) is built from its own repository next to this one.
ROZANEH_SRC ?= ../mahan-vpn

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/ ./cmd/...

# sing-box runs the V2Ray client and server. The official release is
# pinned by version and sha256 (GitHub's published digest).
SINGBOX_VERSION := 1.14.4
SINGBOX_SHA256  := 699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968
SINGBOX_TGZ     := sing-box-$(SINGBOX_VERSION)-linux-amd64.tar.gz

sing-box: bin/sing-box

bin/sing-box:
	mkdir -p bin dist/cache
	test -f dist/cache/$(SINGBOX_TGZ) || curl -fsSL -o dist/cache/$(SINGBOX_TGZ) https://github.com/SagerNet/sing-box/releases/download/v$(SINGBOX_VERSION)/$(SINGBOX_TGZ)
	echo "$(SINGBOX_SHA256)  dist/cache/$(SINGBOX_TGZ)" | sha256sum -c -
	tar -xzf dist/cache/$(SINGBOX_TGZ) -C bin --strip-components=1 sing-box-$(SINGBOX_VERSION)-linux-amd64/sing-box

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
