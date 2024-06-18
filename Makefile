APP = ztman
IMG = $(APP)-xgo
COV = coverage.out
TAG = v$(shell cat VERSION)

.PHONY: dep
dep:
	go mod tidy && go mod vendor

.PHONY: build
build: dep
	goreleaser build --snapshot --clean

.PHONY: build-linux
build-linux: dep
	./hack/build-linux.sh

.PHONY: xgo
xgo:
	docker build -t $(IMG) -f Dockerfile.xgo .

.PHONY: release
release: dep build-linux
	git tag -a $(TAG) -m "$(TAG) release"
	git push origin $(TAG)
	goreleaser release --clean

.PHONY: test
test: unittest govulncheck gosec trufflehog

.PHONY: unittest
unittest:
	go test -v -race -coverprofile=$(COV) ./... \
		&& go tool cover -func $(COV)

.PHONY: govulncheck
govulncheck:
	govulncheck ./...

.PHONY: gosec
gosec:
	gosec ./...

.PHONY: trufflehog
trufflehog:
	trufflehog3
