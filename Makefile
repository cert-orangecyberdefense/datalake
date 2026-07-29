# Make commands for development tests :
test_dev_env:
	@poetry install
	@poetry run black .
	@poetry run pytest $$path

test: lint
	@poetry run pytest $$path

setup-prepush-hook:
	sh setup-prepush-hook.sh

lint:
	@poetry install --only dev --no-root
	@poetry run black . $(flag)

lint_check:
	$(MAKE) --no-print-directory lint flag='--check'


# Make commands that are not supposed to be run manually but through GitHub pipelines :
build_release:
	poetry build

clean:
	@rm -rf dist/
	@echo "Removed dist folder"

deploy_test: clean build_release
	poetry publish --repository testpypi

deploy_prod: clean build_release
	poetry publish


# Make commands to be launched manually by ocd dev
dtl_tag ?= $(shell poetry version -s)
base_python ?= 3.12.12.5490952

build_demisto_image:
	docker build --build-arg "BUILDKIT_DOCKERFILE_CHECK=skip=InvalidDefaultArgInFrom" --no-cache --tag ocddev/demisto-ocd-cti:$(dtl_tag) --build-arg 'DATALAKE_VERSION=$(dtl_tag)' --build-arg 'BASE_BUILDER=$(base_python)' -f demisto/DockerFile .

push_demisto_image:
	docker push ocddev/demisto-ocd-cti:$(dtl_tag)
