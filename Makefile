IMAGE_TAG_BASE ?= quay.io/chrisp262/kmod-signer
IMAGE_TAG ?= $(shell  git log --format="%H" -n 1)
# Image URL to use all building/pushing image targets
IMG ?= $(IMAGE_TAG_BASE):$(IMAGE_TAG)

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

.PHONY: all
all: signimage

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY:  signimage
sign-image: ## Build sign-image binary.
	go build -o $@

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./sign-image.go

.PHONY: image 
image: ## Build docker image with the manager.
	docker build -t $(IMG) .
