FROM registry.fedoraproject.org/fedora as ksource
RUN yum install -y kernel-devel
#FROM registry.access.redhat.com/ubi8-minimal:latest  as ksource
#RUN microdnf -y install kernel-devel 
RUN cp /usr/src/kernels/*/scripts/sign-file /sign-file

FROM golang:1.18 as builder

WORKDIR /workspace

COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download
COPY signimage.go signimage.go
# Build
RUN go build signimage.go

## nasty copying in a binary but it prevents having to yum install kernel-devel to get it
## yum needs subscriptions which the builder may not have.
#COPY sign-file sign-file

#FROM registry.ci.openshift.org/ocp/4.10:base
FROM registry.access.redhat.com/ubi8-minimal:latest

COPY --from=builder /workspace/signimage /
#COPY --from=builder /workspace/sign-file /sign-file
COPY --from=ksource /sign-file /sign-file
#COPY /usr/src/kernels/$(uname -r)/scripts/sign-file /tmp/sign-file

ENTRYPOINT ["/signimage"]
