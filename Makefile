.PHONY: lint lint-check mypy test

lint-check:
	@echo "Running ruff..."
	@ruff check *.py tools/ || { echo "ruff found some issues."; exit 1; }
	@echo "ruff passed!"

lint:
	@echo "Running ruff with fixes..."
	@ruff check --fix *.py tools/ || { echo "ruff found some issues."; exit 1; }
	@echo "ruff passed!"

mypy:
	@echo "Running mypy..."
	@mypy --no-incremental --show-error-codes --ignore-missing-imports *.py tools/ || { echo "Mypy found some issues."; exit 1; }
	@echo "mypy passed!"

test:
	@echo "Running tests..."
	@pytest tests -v || { echo "Tests failed."; exit 1; }
	@echo "Tests passed!"
