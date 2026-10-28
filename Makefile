.PHONY: help install uv-install site test lint typecheck policy redteam keys up down release clean
PY ?= python3

help:            ## list targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/'

install:         ## editable install with dev + api extras
	$(PY) -m pip install -e ".[dev,api]"

uv-install:      ## fast install with uv (https://docs.astral.sh/uv/)
	uv venv && uv pip install -e ".[dev,api,docs]"

site:            ## build the GitHub Pages site into _site/ and print how to preview it
	$(PY) scripts/build_site.py && echo "preview: python -m http.server -d _site 8000"

test:            ## run the full test suite (stdlib unittest; no pytest needed)
	PYTHONPATH=. $(PY) -W ignore -m unittest tests.test_security_pipeline tests.test_extensions

lint:            ## ruff
	ruff check agentshield tests evals

typecheck:       ## mypy (advisory)
	mypy agentshield

policy:          ## strictly validate policies/*.yaml
	PYTHONPATH=. $(PY) -m agentshield policy-validate policies

redteam:         ## seeded mutation red-team (fails below 95% detection / above 5% false positives)
	PYTHONPATH=. $(PY) -W ignore -m agentshield redteam

keys:            ## generate signing keys + secrets into ./keys (gitignored, 0600)
	PYTHONPATH=. $(PY) -m agentshield keygen --out keys

up:              ## start the compose stack (needs .env)
	docker compose up --build -d

down:
	docker compose down

release:         ## build the clean release zip into dist/
	$(PY) scripts/build_release.py

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} + ; rm -rf dist build *.egg-info .mypy_cache .ruff_cache
