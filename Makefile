.DEFAULT_GOAL := help

# Only these trees contain repository-owned Python source.  Keep environment
# directories outside the cleanup scope so `make clean` cannot mutate a live
# runtime or virtual environment.
CLEAN_PYTHON_DIRS := deployment tools tests

.PHONY: help release-check quick smoke e2e clean

help:
	@printf '%s\n' \
	  'Targets:' \
	  '  release-check  Run the complete offline release gate' \
	  '  quick          Fast offline syntax, config, and focused unit gate' \
	  '  smoke          Live health/semantic checks (COMPONENT=name optional)' \
	  '  e2e            Live Kestra canary producer and verifier (HARNESS=kestra)' \
	  '  clean          Remove local generated caches and build output'

release-check:
	bash tools/platform-cli/release-check.sh

quick:
	./test.sh quick

smoke:
	./test.sh smoke $(COMPONENT)

e2e:
	./test.sh e2e $(HARNESS)

clean:
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov build dist
	for directory in $(CLEAN_PYTHON_DIRS); do \
		[ ! -d "$$directory" ] || find "$$directory" \
			\( -type d \( -name .venv -o -name .runtime \) -prune \) -o \
			\( -type d -name __pycache__ -prune -exec rm -rf {} + \) -o \
			\( -type d -name '*.egg-info' -prune -exec rm -rf {} + \) -o \
			\( -type f \( -name '*.pyc' -o -name '*.pyo' \) -exec rm -f {} + \); \
	done
