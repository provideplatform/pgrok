.PHONY: build clean install mod serve stop_local test

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

serve: build
	./ops/run_server.sh

stop_local:
	./ops/stop_local.sh

test: build
	# no-op
