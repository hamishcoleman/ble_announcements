#
all: lint

# Just the packages needed to run lint
PACKAGES+=flake8

build-dep:
	sudo apt-get install $(PACKAGES)

lint:
	flake8
