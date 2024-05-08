SHELL := bash

PYTHONPATH = .

.PHONY: test
test:
	coverage run  -m pytest -s -vv tests/ -x
	coverage report --fail-under=85 -m

.PHONY: fmt
fmt: ## Format the source code using pre-commit hooks
	pre-commit run --all-files
