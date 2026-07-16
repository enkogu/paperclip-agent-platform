.DEFAULT_GOAL := help

.PHONY: help release-check clean

help:
	@printf '%s\n' \
	  'Targets:' \
	  '  release-check  Install development tools and run the offline release gate' \
	  '  clean          Remove local generated caches and build output'

release-check:
	bash tools/platform-cli/release-check.sh

clean:
	rm -rf .runtime .pytest_cache .ruff_cache .coverage htmlcov build dist
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name '*.egg-info' -prune -exec rm -rf {} +
	find . -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
