APP = ztman
COV = coverage.out
TAG = v$(shell cat VERSION)

.PHONY: dep
dep:
	go mod tidy && go mod vendor

.PHONY: builder
builder:
	docker build -t $(APP)-builder .

.PHONY: build
build: dep
	goreleaser build --snapshot --rm-dist

.PHONY: tag
tag:
	git tag -a $(TAG) -m "$(TAG) release"
	git push origin $(TAG)

.PHONY: release
release:
	goreleaser release --rm-dist

.PHONY: test
test: unittest gosec trufflehog

.PHONY: unittest
unittest:
	go test -v -race -coverprofile=$(COV) ./... \
		&& go tool cover -func $(COV)

.PHONY: gosec
gosec:
	gosec ./...

.PHONY: trufflehog
trufflehog:
	trufflehog3 .
