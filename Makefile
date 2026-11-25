
.PHONY: test validate build clean

test:
	pytest -q

validate:
	@for f in audit_profiles/*.audit; do uaudit validate --audit "$$f" || exit 1; done

build:
	python -m build

clean:
	rm -rf build dist .pytest_cache *.egg-info
