## help: Show all available make targets with descriptions
.PHONY: help

help:
	@echo "Olympus — available make targets:"
	@echo ""
	@grep -h "^## " $(MAKEFILE_LIST) | sed 's/^## /  /' | sort
	@echo ""
	@echo "Run 'make <target>' to execute a target."
