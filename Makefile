PYTHON=python

.PHONY: lint test run

lint:
	@echo "No linter configured; running basic syntax check"
	$(PYTHON) -m py_compile $(shell find protocol app tools -name "*.py" 2>/dev/null)

test:
	pytest

run:
	uvicorn app.main:app --reload
