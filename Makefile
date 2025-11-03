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


# Make commands to be launched manually by ocd dev
dtl_tag ?= $(shell python3 -c "import re; f=open('datalake_scripts/cli.py'); m=re.search(r'VERSION\\s*=\\s*[\\\"\\']([^\\\"\\']+)[\\\"\\']', f.read()); print(m.group(1) if m else '3.0.0')")
base_python ?= 3.12.12.5490952

build_demisto_image:
	docker build --build-arg "BUILDKIT_DOCKERFILE_CHECK=skip=InvalidDefaultArgInFrom" --no-cache --tag ocddev/demisto-ocd-cti:$(dtl_tag) --build-arg 'DATALAKE_VERSION=$(dtl_tag)' --build-arg 'BASE_BUILDER=$(base_python)' -f demisto/DockerFile .

push_demisto_image:
	docker push ocddev/demisto-ocd-cti:$(dtl_tag)
