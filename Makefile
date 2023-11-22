# Make commands for development tests :
test_dev_env:
	( \
		python3 -m venv .venv; \
		. .venv/bin/activate; \
		pip install -r requirements.txt; \
		pytest $$path; \
		deactivate \
	)

test:
	@pytest $$path


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
