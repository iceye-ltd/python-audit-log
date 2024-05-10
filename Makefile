SHELL := bash

PYTHONPATH = .

.PHONY: test
test:
	PYTHONPATH=. pytest --cov=audit_log -vv tests


.PHONY: fmt
fmt: ## Format the source code using pre-commit hooks
	pre-commit run --all-files


.PHONY: setup
setup: ## Install project dependencies from requirements-dev.txt
	pip install -r requirements-dev.txt


.PHONY: lint
lint:
	ruff check .
	mypy audit_log
