NAME        := linaudit
SPEC_FILE   := linaudit.spec
VERSION     := $(shell grep '^version' Cargo.toml | head -1 | cut -d '"' -f2 | sed 's/-dev//')
TARBALL     := libaudit.tar.gz

CARGO       ?= cargo
RPMBUILD    ?= rpmbuild
RPMBUILD_FLAGS ?=

.PHONY: all build check test clean dist dist-vendor rpm srpm help

all: build

help:
	@echo "Available build targets:"
	@echo "  build        : Compile release binary (cargo build --release)"
	@echo "  check        : Run cargo check"
	@echo "  test         : Run workspace unit and integration tests"
	@echo "  dist         : Create source tarball ($(TARBALL))"
	@echo "  dist-vendor  : Vendor crates and create offline-ready source tarball"
	@echo "  rpm          : Build binary RPM package using rpmbuild -tb $(TARBALL)"
	@echo "  srpm         : Build source RPM package using rpmbuild -ts $(TARBALL)"
	@echo "  clean        : Remove build artifacts, tarballs, and temporary files"

build:
	$(CARGO) build --release --workspace

check:
	$(CARGO) check --workspace

test:
	$(CARGO) test --workspace

dist: clean-tarball
	tar --exclude='.git' --exclude='target' --exclude='vendor' --exclude='*.tar.gz*' \
		--transform 's,^\.,$(NAME)-$(VERSION),' \
		-czf /tmp/$(TARBALL).$$$$ . && mv /tmp/$(TARBALL).$$$$ $(TARBALL)

dist-vendor: clean-tarball
	$(CARGO) vendor vendor
	tar --exclude='.git' --exclude='target' --exclude='*.tar.gz*' \
		--transform 's,^\.,$(NAME)-$(VERSION),' \
		-czf /tmp/$(TARBALL).$$$$ . && mv /tmp/$(TARBALL).$$$$ $(TARBALL)
	rm -rf vendor .cargo/config.toml

rpm: dist
	$(RPMBUILD) -tb $(TARBALL) $(RPMBUILD_FLAGS)

srpm: dist
	$(RPMBUILD) -ts $(TARBALL) $(RPMBUILD_FLAGS)

clean-tarball:
	rm -f $(TARBALL) $(NAME)-*.tar.gz /tmp/$(TARBALL).*

clean: clean-tarball
	$(CARGO) clean
	rm -rf vendor
