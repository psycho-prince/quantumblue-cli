# Simple Makefile for QuantumBlue CLI
BINARY_NAME=qb

build:
	go build -o ${BINARY_NAME} ./cmd/qb/main.go

test:
	go test ./internal/...

release-snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -f ${BINARY_NAME}
	rm -rf dist/
