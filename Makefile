export GO111MODULE=on
GOARCH=amd64
UNIX_BINARY=captionthis-api
WINDOWS_BINARY=captionthis-api.exe

all: linux windows test vet fmt clean update tidy

linux:
	cd cmd && \
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -o $(UNIX_BINARY) . && \
	mv $(UNIX_BINARY) ../$(UNIX_BINARY) && \
	cd - > /dev/null

windows:
	cd cmd && \
	CGO_ENABLED=0 GOOS=windows GOARCH=$(GOARCH) go build -o $(WINDOWS_BINARY) . && \
	mv $(WINDOWS_BINARY) ../$(WINDOWS_BINARY) && \
	cd - > /dev/null

lint:
	golint

test:
	go test -v ./...

vet:
	go vet ./...

fmt:
	go fmt ./...

clean:
	go clean && \
	rm -f $(UNIX_BINARY) && \
	rm -f $(WINDOWS_BINARY)

update:
	go mod download

tidy:
	go mod tidy

.PHONY: all linux windows test vet fmt clean update tidy