.DEFAULT_GOAL := help
SHELL := bash

GOFLAGS := 
PROGRAM := main

.PHONY: deps
deps:
	@echo "==> Installing dependencies"
	if ! command -V govvv; then go get -u github.com/ahmetb/govvv; go mod tidy; fi

.PHONY: build
build: clean deps ## Build the program for Linux
	@echo "==> Building the program for Linux"
	$(GOFLAGS) CGO_ENABLED=0 GOOS=linux govvv build -v -a -o $(PROGRAM)

clean: ## Clean temporary files
	@echo "==> Cleaning temporary files"
	go clean
	rm -f $(PROGRAM)

.PHONY: docker
docker: ## Build a docker image for local dev
	docker build -t drone-github-comment:local .

.PHONY: test
test: ## Run all tests
	#TODO: Update this when tests are created
	$(GOFLAGS) go test ./...

.PHONY: help
help:  ## Print list of Makefile targets.
	@# Taken from https://github.com/spf13/hugo/blob/master/Makefile
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  cut -d ":" -f1- | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
