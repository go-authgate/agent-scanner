GO ?= go
EXECUTABLE := agent-scanner
GOFILES := $(shell find . -type f -name "*.go")
TAGS ?=

ifneq ($(shell uname), Darwin)
	EXTLDFLAGS = -extldflags "-static" $(null)
else
	EXTLDFLAGS =
endif

ifneq ($(DRONE_TAG),)
	VERSION ?= $(DRONE_TAG)
else
	VERSION ?= $(shell git describe --tags --always || git rev-parse --short HEAD)
endif
COMMIT ?= $(shell git rev-parse --short HEAD)

LDFLAGS ?= -X 'github.com/go-authgate/agent-scanner/internal/version.Version=$(VERSION)' \
	-X 'github.com/go-authgate/agent-scanner/internal/version.BuildTime=$(shell date +%Y-%m-%dT%H:%M:%S)' \
	-X 'github.com/go-authgate/agent-scanner/internal/version.GitCommit=$(shell git rev-parse HEAD)' \
	-X 'github.com/go-authgate/agent-scanner/internal/version.GoVersion=$(shell $(GO) version | cut -d " " -f 3)' \
	-X 'github.com/go-authgate/agent-scanner/internal/version.BuildOS=$(shell $(GO) env GOOS)' \
	-X 'github.com/go-authgate/agent-scanner/internal/version.BuildArch=$(shell $(GO) env GOARCH)'

all: build

## build: build the agent-scanner binary
build: $(EXECUTABLE)

$(EXECUTABLE): $(GOFILES)
	$(GO) build -v -tags '$(TAGS)' -ldflags '$(EXTLDFLAGS)-s -w $(LDFLAGS)' -o bin/$@ ./cmd/agent-scanner

## install: install the agent-scanner binary
install: $(GOFILES)
	$(GO) install -v -tags '$(TAGS)' -ldflags '$(EXTLDFLAGS)-s -w $(LDFLAGS)' ./cmd/agent-scanner

## test: run tests
test:
	@$(GO) test -v -cover -coverprofile coverage.txt ./... && echo "\n==>\033[32m Ok\033[m\n" || exit 1

## coverage: view test coverage in browser
coverage: test
	$(GO) tool cover -html=coverage.txt

## fmt: format go files using golangci-lint
fmt:
	$(GO) tool golangci-lint fmt

## lint: run golangci-lint to check for issues
lint:
	$(GO) tool golangci-lint run

## vet: run go vet
vet:
	$(GO) vet ./...

## build_linux_amd64: build the agent-scanner binary for linux amd64
build_linux_amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -a -tags '$(TAGS)' -ldflags '$(EXTLDFLAGS)-s -w $(LDFLAGS)' -o release/linux/amd64/$(EXECUTABLE) ./cmd/agent-scanner

## build_linux_arm64: build the agent-scanner binary for linux arm64
build_linux_arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -a -tags '$(TAGS)' -ldflags '$(EXTLDFLAGS)-s -w $(LDFLAGS)' -o release/linux/arm64/$(EXECUTABLE) ./cmd/agent-scanner

## build_darwin_amd64: build the agent-scanner binary for darwin amd64
build_darwin_amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build -a -tags '$(TAGS)' -ldflags '-s -w $(LDFLAGS)' -o release/darwin/amd64/$(EXECUTABLE) ./cmd/agent-scanner

## build_darwin_arm64: build the agent-scanner binary for darwin arm64
build_darwin_arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -a -tags '$(TAGS)' -ldflags '-s -w $(LDFLAGS)' -o release/darwin/arm64/$(EXECUTABLE) ./cmd/agent-scanner

## build_windows_amd64: build the agent-scanner binary for windows amd64
build_windows_amd64:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -a -tags '$(TAGS)' -ldflags '$(EXTLDFLAGS)-s -w $(LDFLAGS)' -o release/windows/amd64/$(EXECUTABLE).exe ./cmd/agent-scanner

## clean: remove build artifacts and test coverage
clean:
	rm -rf bin/ release/ coverage.txt

## rebuild: clean and build
rebuild: clean build

.PHONY: help build install test coverage fmt lint vet clean rebuild
.PHONY: build_linux_amd64 build_linux_arm64
.PHONY: build_darwin_amd64 build_darwin_arm64 build_windows_amd64
.PHONY: mod-download mod-tidy mod-verify check-tools version

## mod-download: download go module dependencies
mod-download:
	$(GO) mod download

## mod-tidy: tidy go module dependencies
mod-tidy:
	$(GO) mod tidy

## mod-verify: verify go module dependencies
mod-verify:
	$(GO) mod verify

## check-tools: verify Go is installed
check-tools:
	@command -v $(GO) >/dev/null 2>&1 || (echo "Go not found" && exit 1)

## version: display version information
version:
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Go Version: $(shell $(GO) version)"

## help: print this help message
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'
