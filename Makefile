.PHONY: help install install-dev test test-cov lint clean build upload docker docker-build docker-run

help:
	@echo "KTScan - Available Commands"
	@echo "========================================"
	@echo "Development:"
	@echo "  install      Install production dependencies"
	@echo "  install-dev  Install development dependencies"
	@echo "  install-e    Install in editable mode"
	@echo ""
	@echo "Testing:"
	@echo "  test         Run tests"
	@echo "  test-cov     Run tests with coverage report"
	@echo "  test-quick   Run quick tests"
	@echo ""
	@echo "Code Quality:"
	@echo "  lint         Run code linting"
	@echo "  format       Format code"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build Build Docker image"
	@echo "  docker-run   Run with Docker"
	@echo "  docker-dev   Run development container"
	@echo ""
	@echo "Distribution:"
	@echo "  clean        Clean build artifacts"
	@echo "  build        Build distribution packages"
	@echo "  upload       Upload to PyPI (requires twine)"
	@echo ""
	@echo "Usage Examples:"
	@echo "  make install-e                    # Install for development"
	@echo "  make docker-build                 # Build Docker image"
	@echo "  make docker-run ARGS=example.com  # Run Docker scan"

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements-dev.txt

install-e: install
	pip install -e .

test:
	pytest tests/

test-cov:
	pytest tests/ --cov=ktscan --cov-report=html --cov-report=term-missing

test-quick:
	pytest tests/unit/checks/ --tb=short -q

lint:
	flake8 ktscan/
	black --check ktscan/
	mypy ktscan/

format:
	black ktscan/
	black tests/

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*~" -delete

build: clean
	python setup.py sdist bdist_wheel

upload: build
	twine upload dist/*

# Docker commands
docker-build:
	docker build -t ktscan:latest .

docker-run: docker-build
	docker run --rm ktscan:latest $(ARGS)

docker-dev:
	docker-compose --profile dev run ktscan-dev

docker-compose-run:
	docker-compose run ktscan $(ARGS)

# Development shortcuts
dev-setup: install-dev install-e
	@echo "Development environment ready!"
	@echo "Run: ktscan --help"

quick-scan:
	./bin/ktscan $(ARGS)

# Example targets
example-local:
	ktscan example.com

example-docker:
	make docker-run ARGS="example.com"

example-json:
	ktscan --format json example.com