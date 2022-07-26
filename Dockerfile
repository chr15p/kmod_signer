FROM registry.access.redhat.com/ubi8/ubi as builder

WORKDIR /workspace
RUN dnf install -y kernel-devel golang

COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download
COPY signimage.go signimage.go
# Build
RUN go build signimage.go


#FROM registry.ci.openshift.org/ocp/4.10:base
FROM registry.access.redhat.com/ubi8-minimal:latest

COPY --from=builder /workspace/signimage /
COPY --from=builder /usr/src/kernels/*/scripts/sign-file /sign-file
#COPY /usr/src/kernels/$(uname -r)/scripts/sign-file /tmp/sign-file

ENTRYPOINT ["/signimage"]
