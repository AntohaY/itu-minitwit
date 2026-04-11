# --- 1. Colors & Variables ---
RED    := $(shell tput -Txterm setaf 1)
GREEN  := $(shell tput -Txterm setaf 2)
CYAN   := $(shell tput -Txterm setaf 6)
RESET  := $(shell tput -Txterm sgr0)

GO_DIR=new
DOCKER_FILES=$(shell find . -name "Dockerfile*")

ci-setup:
	@echo "$(CYAN)==> Starting containers in background...$(RESET)"
	docker compose up -d --build
	@echo "Waiting for webserver to be healthy..."
	sleep 15 

ci-cleanup:
	@echo "$(CYAN)==> Tearing down Docker environment...$(RESET)"
	docker compose down -v

# ---------- Tests ---------------

# The Simulator: Captures output, fails fast, and reports errors
test-sim:
	@echo "$(CYAN)==> Running simulator...$(RESET)"
	@python3 -m pip install requests --user -q
	@tmpfile=$$(mktemp); \
	timeout 500s python3 minitwit_simulator.py http://localhost:8080 >"$$tmpfile" 2>&1; \
	EXIT_STATUS=$$?; \
	if [ $$EXIT_STATUS -ne 0 ]; then \
		echo "$(RED)Simulator Failed (Exit Code: $$EXIT_STATUS)$(RESET)"; \
		echo "--- Communication from Simulator ---"; \
		cat "$$tmpfile"; \
		rm -f "$$tmpfile"; \
		exit 1; \
	else \
		echo "$(GREEN)Simulator finished perfectly with zero errors!$(RESET)"; \
		rm -f "$$tmpfile"; \
	fi

fmt:
	@echo "$(CYAN)==> Formatting Go code...$(RESET)"
	cd $(GO_DIR) && go fmt ./...

lint-go:
	@echo "$(CYAN)==> Running staticcheck...$(RESET)"
	cd $(GO_DIR) && golangci-lint run ./...

lint-docker:
	@echo "$(CYAN)==> Running Hadolint on all Dockerfiles...$(RESET)"
	@$(foreach file,$(DOCKER_FILES), \
		echo "Linting $(file)"; \
		docker run --rm -i hadolint/hadolint < $(file) || exit 1; \
	)

test:
	@echo "$(CYAN)==> Running Go unit tests...$(RESET)"
	cd $(GO_DIR) && go test -v ./...

# --------- Execute tests --------------------------

# if one test file, still environment is cleaned up correctly
verify:
	@$(MAKE) ci-setup
	@$(MAKE) run-checks || (ret=$$?; $(MAKE) ci-cleanup; exit $$ret)
	@$(MAKE) ci-cleanup
	@echo "$(GREEN) All checks passed and environment cleaned!$(RESET)"

# Helper to group all checks together
run-checks: test-sim fmt lint-go lint-docker test

.PHONY: ci-setup test-sim fmt lint-go lint-docker test verify ci-cleanup run-checks