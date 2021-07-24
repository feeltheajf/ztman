APP = ztman
COV = coverage.out
TAG = v$(shell cat VERSION)

.PHONY: dep
dep:
	go mod tidy && go mod vendor

.PHONY: builder
builder:
	docker build -t $(APP)-builder .

.PHONY: release
release: dep
	git tag -a $(TAG) -m "$(TAG) release"
	git push origin $(TAG)
	docker run --rm -it \
		-v ${CURDIR}:/ztman \
		-e GITHUB_TOKEN \
		$(APP)-builder

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
