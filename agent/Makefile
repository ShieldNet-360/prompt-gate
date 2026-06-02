AGENT_BINARY := prompt-gate-agent
PKG := ./...

.PHONY: build
build:
	go build -o $(AGENT_BINARY) ./cmd/agent

.PHONY: test
test:
	go test -race $(PKG)

.PHONY: lint
lint:
	go vet $(PKG)

.PHONY: dlp-bench
dlp-bench:
	go test -v ./internal/dlp -run TestFPCorpus

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: clean
clean:
	rm -f $(AGENT_BINARY)
