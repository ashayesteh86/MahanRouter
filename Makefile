VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test lab cross clean

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/ ./cmd/...

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
