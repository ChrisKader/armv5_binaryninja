# Convenience wrapper - delegates to .build directory

.PHONY: all build install clean configure

all: build

configure:
	@mkdir -p .build
	@cd .build && cmake ..

build: configure
	@$(MAKE) -C .build -j8

install: build
	@$(MAKE) -C .build install_plugin

clean:
	@rm -rf .build
