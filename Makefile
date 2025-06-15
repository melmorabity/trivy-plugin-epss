export VIRTUAL_ENV := $(PWD)/.venv
export PATH := $(VIRTUAL_ENV)/bin:$(PATH)

VIRTUAL_ENV_STAMP = $(VIRTUAL_ENV)/.stamp
PLUGIN_NAME := $(shell yq '.name' plugin.yaml)
PLUGIN_VERSION := $(shell yq '.version' plugin.yaml)
TARBALL = trivy-plugin-$(PLUGIN_NAME)-$(PLUGIN_VERSION).tar.gz

all: lint test

$(VIRTUAL_ENV)/bin/python:
	python3 -m venv --prompt $(VIRTUAL_ENV) $(VIRTUAL_ENV)

$(VIRTUAL_ENV_STAMP): pyproject.toml $(VIRTUAL_ENV)/bin/python
	pip install -e .[dev] -e .[test]
	touch $@

virtualenv: $(VIRTUAL_ENV_STAMP)

lint: virtualenv
	pre-commit run -a

test: virtualenv
	tox

$(TARBALL): plugin.yaml epss.py LICENSE
	tar -czf $@ $^

tarball: $(TARBALL)

install: $(TARBALL)
	trivy plugin install $<

uninstall:
	trivy plugin uninstall $(PLUGIN_NAME)

pre-commit-autoupdate: virtualenv
	pre-commit autoupdate

clean:
	$(RM) $(TARBALL)

mrproper: clean
	$(RM) -r $(VIRTUAL_ENV) .*_cache .tox *.egg-info

.PHONY: all clean install lint mrproper pre-commit-update tarball test uninstall virtualenv

.DEFAULT_GOAL: all
