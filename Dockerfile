FROM registry.fedoraproject.org/fedora as ksource
RUN yum install -y kernel-devel
RUN cp /usr/src/kernels/*/scripts/sign-file /sign-file

FROM golang:1.18 as builder

WORKDIR /workspace

COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download
COPY signimage.go signimage.go
# Build
RUN go build signimage.go

FROM registry.fedoraproject.org/fedora

COPY --from=builder /workspace/signimage /
COPY --from=ksource /sign-file /sign-file

ENTRYPOINT ["/signimage"]
