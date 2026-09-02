# lightphe4j
#
# Thin wrappers around Maven so the common tasks have short names. Every target
# is just Maven underneath, so anything here can also be run directly.
#
# You do not need Maven installed: ./mvnw downloads it. You do need a JDK 17 or
# newer, which `scripts/java-home.sh` locates for you -- a stale JAVA_HOME in
# your shell profile will not break the build. Run `make doctor` to see which
# JDK was picked, or override it explicitly:
#
#     make test JAVA_HOME=/path/to/jdk-17

MVN ?= ./mvnw
ifeq ($(wildcard ./mvnw),)
MVN := mvn
endif

# Resolved once, then handed to every Maven invocation. Empty when no suitable
# JDK exists; the require-jdk guard below turns that into a readable error.
JAVA_HOME := $(shell ./scripts/java-home.sh 2>/dev/null)
export JAVA_HOME

.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------
# Help and diagnostics
# ---------------------------------------------------------------------------

.PHONY: help
help: ## show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: doctor
doctor: ## show which JDK and Maven the build will use
	@if [ -n "$(JAVA_HOME)" ]; then \
		echo "JAVA_HOME : $(JAVA_HOME)"; \
		printf "java      : "; "$(JAVA_HOME)/bin/java" -version 2>&1 | head -1; \
	else \
		./scripts/java-home.sh; \
	fi
	@printf "maven     : "; $(MVN) --version 2>/dev/null | head -1 || echo "not available"

# Every Maven target depends on this, so a missing JDK fails with the
# explanation from scripts/java-home.sh rather than Maven's opaque
# "JAVA_HOME environment variable is not defined correctly".
.PHONY: require-jdk
require-jdk:
	@test -n "$(JAVA_HOME)" || ./scripts/java-home.sh

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

.PHONY: test
test: require-jdk ## run the unit tests
	$(MVN) test

.PHONY: test-one
test-one: require-jdk ## run a single test class, e.g. make test-one T=PaillierTest
	@test -n "$(T)" || { echo "usage: make test-one T=PaillierTest"; exit 1; }
	$(MVN) test -Dtest=$(T)

.PHONY: test-slow
test-slow: require-jdk ## also run the tests that are disabled by default (curve sweep, large keys)
	$(MVN) test -Djunit.jupiter.conditions.deactivate='*'

.PHONY: cover
cover: require-jdk ## run the tests and write the coverage report to target/site/jacoco
	$(MVN) clean verify
	@echo "coverage report: target/site/jacoco/index.html"

# ---------------------------------------------------------------------------
# Formatting and linting
# ---------------------------------------------------------------------------

.PHONY: format
format: require-jdk ## rewrite the sources with the project code style
	$(MVN) spotless:apply

.PHONY: fmt
fmt: format ## alias for format

.PHONY: format-check
format-check: require-jdk ## fail if any source is not formatted
	$(MVN) spotless:check

.PHONY: checkstyle
checkstyle: require-jdk ## run checkstyle only
	$(MVN) checkstyle:check

.PHONY: spotbugs
spotbugs: require-jdk ## run the static analyser only
	$(MVN) compile spotbugs:check

.PHONY: lint
lint: format-check checkstyle spotbugs ## check formatting, style and static analysis

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

.PHONY: compile
compile: require-jdk ## compile the main sources
	$(MVN) compile

.PHONY: build
build: require-jdk ## build the jar, sources jar and javadoc jar (skips tests)
	$(MVN) -DskipTests package

.PHONY: verify
verify: require-jdk ## clean, compile, test, package and run the full verification chain
	$(MVN) clean verify

.PHONY: install
install: require-jdk ## install the artifacts into the local ~/.m2 repository
	$(MVN) clean install

.PHONY: javadoc
javadoc: require-jdk ## generate the API documentation into target/reports/apidocs
	$(MVN) javadoc:javadoc
	@echo "javadoc: target/reports/apidocs/index.html"

.PHONY: clean
clean: require-jdk ## remove the build output
	$(MVN) clean

.PHONY: deps
deps: require-jdk ## show the dependency tree
	$(MVN) dependency:tree

.PHONY: versions
versions: require-jdk ## report dependency and plugin updates
	$(MVN) versions:display-dependency-updates versions:display-plugin-updates

# ---------------------------------------------------------------------------
# Release
# ---------------------------------------------------------------------------
#
# Releasing is a deliberate local action, not something CI does. It needs a GPG
# key for signing and Central Portal credentials under the server id "central"
# in ~/.m2/settings.xml:
#
#     <server>
#       <id>central</id>
#       <username>...</username>
#       <password>...</password>
#     </server>

.PHONY: release-check
release-check: require-jdk ## dry run of the release build: sign and package without uploading
	$(MVN) clean verify -Prelease

.PHONY: release
release: require-jdk ## sign and upload the artifacts to Maven Central
	$(MVN) clean deploy -Prelease

.PHONY: push-release
push-release: release ## alias for release, mirroring scripts/push-release.sh in LightPHE

.PHONY: ci
ci: lint verify ## what the GitHub Actions workflow runs
