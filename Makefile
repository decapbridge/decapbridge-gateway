.PONY: all build deps image lint test
CHECK_FILES?=$$(go list ./... | grep -v /vendor/)

APPLICATION_NAME:=$(notdir $(CURDIR))

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {sub("\\\\n",sprintf("\n%22c"," "), $$2);printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: lint vet test build ## Run the tests and build the binary.

build: ## Build the binary.
	go build -ldflags "-X github.com/netlify/git-gateway/cmd.Version=$(SOURCE_COMMIT)"

deps: ## Install dependencies.
	@go get -u golang.org/x/lint/golint
	@go mod download

image: ## Build the Docker image.
	docker build .

lint: ## Lint the code
	golint $(CHECK_FILES)

vet: # Vet the code
	go vet $(CHECK_FILES)

test: ## Run tests.
	go test -v $(CHECK_FILES)

docker-build:
	docker build -t $(APPLICATION_NAME) .

docker-run: docker-build
	docker run --env-file .env -p 8081:8081 $(APPLICATION_NAME)
