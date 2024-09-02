# Make commands for development tests :
test_dev_env:
	@( \
		python3 -m venv .venv > /dev/null 2>&1; \
		. .venv/bin/activate > /dev/null 2>&1; \
		pip install -r requirements.txt > /dev/null 2>&1; \
		pip install . > /dev/null 2>&1; \
		black .; \
		pytest $$path; \
		deactivate > /dev/null 2>&1 \
	)

test: lint
	@pytest $$path

setup-prepush-hook:
	sh setup-prepush-hook.sh

lint:
	@( \
		python3 -m venv .venv > /dev/null 2>&1; \
		. .venv/bin/activate > /dev/null 2>&1; \
		pip install -r requirements.txt > /dev/null 2>&1; \
		pip install . > /dev/null 2>&1; \
		black . $(flag); \
		deactivate > /dev/null 2>&1 \
	)

lint_check: 
	$(MAKE) --no-print-directory lint flag='--check'


# Make commands that are not supposed to be run manually but through GitHub pipelines :
build_release:
	python3 setup.py sdist bdist_wheel

clean:
	@rm -rf dist/
	@echo "Removed dist folder"

deploy_test: clean build_release
	python3 -m twine upload --repository testpypi dist/*

deploy_prod: clean build_release
	python3 -m twine upload dist/*
