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

.PHONY: release
release: dep
	git tag -a $(TAG) -m "$(TAG) release"
	git push origin $(TAG)
	goreleaser release --rm-dist
	docker run --rm -it \
		-v ${CURDIR}:/ztman \
		-e GITHUB_TOKEN \
		$(APP)-builder \
		release \
		--rm-dist \
		--config .goreleaser.linux.yml

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
