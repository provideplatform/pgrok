.PHONY: build clean install mod run_server stop_local test

clean:
	rm -rf ./.bin 2>/dev/null || true
	rm ./pgrok 2>/dev/null || true
	go fix ./...
	go clean -i ./...

build: clean mod
	go fmt ./...
	go build -v -o ./.bin/pgrok_client ./cmd/client
	go build -v -o ./.bin/pgrok_server ./cmd/server

install: clean
	go install ./...

lint:
	./ops/lint.sh

mod:
	go mod init 2>/dev/null || true
	go mod tidy
	go mod vendor 

run_api: build run_local_dependencies
	./ops/run_api.sh

stop_local:
	./ops/stop_local.sh

test: build
	# no-op
