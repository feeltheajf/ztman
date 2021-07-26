APP = ztman
IMG = $(APP)-builder
COV = coverage.out
TAG = v$(shell cat VERSION)

.PHONY: dep
dep:
	go mod tidy && go mod vendor

.PHONY: builder
builder:
	docker build -t $(IMG) .

.PHONY: build
build: dep build-linux
	goreleaser build --snapshot --rm-dist

.PHONY: build-linux
build-linux:
	docker run --rm -it \
		-v ${CURDIR}:/ztman \
		$(IMG) \
		build \
		--snapshot \
		--rm-dist \
		--config .goreleaser.linux.yml

.PHONY: release
release: dep release-linux
	git tag -a $(TAG) -m "$(TAG) release"
	git push origin $(TAG)
	goreleaser release --rm-dist

.PHONY: release-linux
release-linux:
	git tag -a $(TAG)-linux -m "$(TAG)-linux release"
	git push origin $(TAG)-linux
	docker run --rm -it \
		-v ${CURDIR}:/ztman \
		-e GITHUB_TOKEN \
		$(IMG) \
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
