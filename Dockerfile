#FROM registry.ci.openshift.org/ocp/4.10:base
FROM registry.access.redhat.com/ubi8-minimal:latest

COPY ./signimage /
COPY ./sign-file /tmp/sign-file
#COPY /usr/src/kernels/$(uname -r)/scripts/sign-file /tmp/sign-file

ENTRYPOINT ["/signimage"]
