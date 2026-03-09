.PHONY: lint lint-check mypy test build build-eks eks-ecr-create eks-push eks-deploy

# --- Docker & EKS ---
# ECR repo (same as in .github/workflows/docker.yml). Build and push before deploying to EKS.
AWS_REGION ?= us-west-2
ECR_REGISTRY := 266735823956.dkr.ecr.$(AWS_REGION).amazonaws.com
ECR_REPO := $(ECR_REGISTRY)/vijil-travel-agent
IMAGE_TAG ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "latest")

build:
	docker build -t vijil-travel-agent:$(IMAGE_TAG) -t vijil-travel-agent:latest .

# Build for linux/amd64 (EKS nodes). Required when building on arm64 (e.g. Mac M1/M2).
build-eks:
	docker build --platform linux/amd64 -t vijil-travel-agent:$(IMAGE_TAG) -t vijil-travel-agent:latest .

# Push image to ECR. Requires: AWS CLI configured, ECR repo to exist (make eks-ecr-create).
# Uses build-eks so the image is linux/amd64 and can run on EKS nodes.
eks-push: build-eks
	aws ecr get-login-password --region $(AWS_REGION) | docker login --username AWS --password-stdin $(ECR_REGISTRY) && \
	docker tag vijil-travel-agent:$(IMAGE_TAG) $(ECR_REPO):$(IMAGE_TAG) && \
	docker tag vijil-travel-agent:$(IMAGE_TAG) $(ECR_REPO):latest && \
	docker push $(ECR_REPO):$(IMAGE_TAG) && \
	docker push $(ECR_REPO):latest && \
	echo "Pushed $(ECR_REPO):$(IMAGE_TAG) and :latest"

# Create ECR repository (one-time). Requires AWS CLI with permission to create repos.
eks-ecr-create:
	aws ecr describe-repositories --repository-names vijil-travel-agent --region $(AWS_REGION) 2>/dev/null || \
	aws ecr create-repository --repository-name vijil-travel-agent --region $(AWS_REGION)

# Deploy to EKS (namespace vijil-sample-agents). Run eks-push first.
eks-deploy: eks-push
	kubectl apply -f k8s/deployment-eks.yaml
	@echo "Run: kubectl rollout status deployment/vijil-travel-agent -n vijil-sample-agents"

lint-check:
	@echo "Running ruff..."
	@ruff check *.py tools/ routes/ db/ || { echo "ruff found some issues."; exit 1; }
	@echo "ruff passed!"

lint:
	@echo "Running ruff with fixes..."
	@ruff check --fix *.py tools/ routes/ db/ || { echo "ruff found some issues."; exit 1; }
	@echo "ruff passed!"

mypy:
	@echo "Running mypy..."
	@mypy --no-incremental --show-error-codes --ignore-missing-imports *.py tools/ routes/ db/ || { echo "Mypy found some issues."; exit 1; }
	@echo "mypy passed!"

test:
	@echo "Running tests..."
	@pytest tests -v || { echo "Tests failed."; exit 1; }
	@echo "Tests passed!"
