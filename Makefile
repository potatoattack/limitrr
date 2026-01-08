BINARY_NAME=limitrr

.PHONY: all build run clean test

all: build

build:
	@echo "Building $(BINARY_NAME)"
	GOAMD64=v3 go build -ldflags="-s -w" -o $(BINARY_NAME) main.go

run:
	go run main.go

clean:
	@echo "Cleaning..."
	go clean
	rm -f $(BINARY_NAME)
