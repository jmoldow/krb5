.PHONY: all
all: config build

.PHONY: config
config:
	cd src && ./util/reconf && ./configure

.PHONY: build
build: config
	make --directory=./src/

.PHONY: clean
clean:
	make --directory=./src/ clean

