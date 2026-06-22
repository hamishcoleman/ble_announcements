#
all: lint test

# Just the packages needed to run lint
PACKAGES+=flake8
PACKAGES+=python3-pytest
PACKAGES+=python3-pytest-cov

build-dep:
	sudo apt-get install $(PACKAGES)

lint:
	flake8

test:
	pytest-3 \
		--cov-report=term-missing \
		--cov-report=html \
		--cov-fail-under=42 \
		--cov=. \
		ble_listen.py \
		bthome2influx.py \
		python3/hc/ble.py
