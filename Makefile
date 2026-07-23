BINARY_NAME=qb
BUILD_DIR=bin

.PHONY: all build test clean release

all: test build

build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/pqc-cli/main.go

test:
	go test ./internal/...

clean:
	rm -rf $(BUILD_DIR)
	rm -f *.pqc *.decrypted *.audit inventory.json

release:
	goreleaser release --clean
