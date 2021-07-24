FROM golang:1.16.6-stretch
LABEL maintainer="Ilya Radostev <feeltheajf@gmail.com>"

RUN apt-get update -y \
    && apt-get install -y libpcsclite-dev \
    && go install github.com/goreleaser/goreleaser@latest

CMD [ "goreleaser", "release" ]
