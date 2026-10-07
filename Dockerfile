# syntax=docker/dockerfile:1

# Cross-compiled on the build platform, so no emulation is needed for Go
FROM --platform=$BUILDPLATFORM golang:1.27-alpine3.24 AS build
ARG TARGETOS TARGETARCH TARGETVARIANT
# A release tag (e.g. v1.2.0) to stamp in; other builds report a pseudo-version
ARG VERSION=""
# git lets go build stamp the commit, as it does for the release binaries
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
	CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" GOARM="${TARGETVARIANT#v}" \
	go build -trimpath -ldflags "-s -w${VERSION:+ -X main.version=${VERSION}}" -o /smbproxy .

FROM alpine:3.24

RUN apk add --no-cache tzdata

COPY --from=build /smbproxy /usr/local/bin/smbproxy
RUN smbproxy -version

# Mount the configuration (and any password files it names) here. Until then
# the example runs, with placeholders for the password files it names; its
# targets do not exist, so its shares cannot be opened.
WORKDIR /etc/smbproxy
COPY --chmod=600 smbproxy.example.yaml smbproxy.yaml
RUN for f in local.pass corp-admin.pass; do echo change-me > "$f"; done && chmod 600 *.pass

EXPOSE 445

ENTRYPOINT ["/usr/local/bin/smbproxy"]
CMD ["-config", "/etc/smbproxy/smbproxy.yaml"]
