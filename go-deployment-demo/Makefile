.PHONY: help build test run docker-build docker-run docker-stop clean k8s-deploy k8s-delete lint

# Variables
APP_NAME=go-deployment-demo
VERSION=1.0.0
DOCKER_IMAGE=$(APP_NAME):$(VERSION)
GO=go
GOFLAGS=-v
LDFLAGS=-ldflags "-w -s"

help: ## Display this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the Go binary
	@echo "Building $(APP_NAME)..."
	$(GO) build $(LDFLAGS) -o $(APP_NAME).exe .

build-linux: ## Build Linux binary
	@echo "Building $(APP_NAME) for Linux..."
	CGO_ENABLED=0 GOOS=linux $(GO) build $(LDFLAGS) -o $(APP_NAME) .

test: ## Run tests
	@echo "Running tests..."
	$(GO) test -v ./...

test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	$(GO) test -v -cover -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

run: ## Run the application locally
	@echo "Running $(APP_NAME)..."
	$(GO) run main.go

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -f $(APP_NAME).exe $(APP_NAME)
	rm -f coverage.out coverage.html
	rm -rf vendor

lint: ## Run linter
	@echo "Running linter..."
	golangci-lint run || echo "Install golangci-lint: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"

fmt: ## Format code
	@echo "Formatting code..."
	$(GO) fmt ./...

vet: ## Run go vet
	@echo "Running go vet..."
	$(GO) vet ./...

docker-build: ## Build Docker image
	@echo "Building Docker image $(DOCKER_IMAGE)..."
	docker build -t $(DOCKER_IMAGE) -t $(APP_NAME):latest .

docker-run: ## Run Docker container
	@echo "Running Docker container..."
	docker run -d --name $(APP_NAME) -p 8080:8080 -e ENVIRONMENT=production $(DOCKER_IMAGE)
	@echo "Container running on http://localhost:8080"

docker-stop: ## Stop and remove Docker container
	@echo "Stopping Docker container..."
	docker stop $(APP_NAME) || true
	docker rm $(APP_NAME) || true

docker-logs: ## View Docker container logs
	docker logs -f $(APP_NAME)

docker-shell: ## Execute shell in Docker container
	docker exec -it $(APP_NAME) sh

docker-push: ## Push Docker image to registry
	@echo "Pushing $(DOCKER_IMAGE) to registry..."
	docker push $(DOCKER_IMAGE)

k8s-deploy: ## Deploy to Kubernetes
	@echo "Deploying to Kubernetes..."
	kubectl apply -f k8s/

k8s-delete: ## Delete from Kubernetes
	@echo "Deleting from Kubernetes..."
	kubectl delete -f k8s/

k8s-status: ## Check Kubernetes deployment status
	@echo "Deployment status:"
	kubectl get deployments
	@echo "\nPods:"
	kubectl get pods
	@echo "\nServices:"
	kubectl get svc

k8s-logs: ## View Kubernetes pod logs
	kubectl logs -l app=$(APP_NAME) --tail=50 -f

k8s-port-forward: ## Forward Kubernetes service to localhost
	kubectl port-forward svc/$(APP_NAME) 8080:80

all: test build docker-build ## Run tests, build binary and Docker image

dev: ## Run in development mode with auto-reload (requires air)
	air || echo "Install air: go install github.com/air-verse/air@latest"
