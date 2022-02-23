build_release:
	python3 setup.py sdist bdist_wheel
clean:
	@rm -rf dist/
	@echo "Removed dist folder"
test:
	@pytest $$path
deploy_test: clean build_release
	python3 -m twine upload --repository testpypi dist/*
deploy_prod: clean build_release
	python3 -m twine upload dist/*
