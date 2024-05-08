SHELL := bash

PYTHONPATH = .

.PHONY: test
test:
	pytest --cov=audit_log -vv tests


.PHONY: fmt
fmt: ## Format the source code using pre-commit hooks
	pre-commit run --all-files
