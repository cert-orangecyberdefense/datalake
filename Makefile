# Make commands for development tests :
test_dev_env:
	( \
		python3 -m venv .venv; \
		. .venv/bin/activate; \
		pip install -r requirements.txt; \
		pip install .; \
		black .; \
		pytest $$path; \
		deactivate \
	)

test: lint
	@pytest $$path

setup-prepush-hook:
	sh setup-prepush-hook.sh

lint:
	black .

lint_check: lint


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
