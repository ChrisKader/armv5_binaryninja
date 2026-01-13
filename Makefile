# Convenience wrapper - delegates to .build directory

.PHONY: all build install install_plugin clean configure

all: build

configure:
	@mkdir -p .build
	@cd .build && cmake ..

build: configure
	@$(MAKE) -C .build -j8

install: build
	@$(MAKE) -C .build install_plugin

install_plugin: install

clean:
	@rm -rf .build
