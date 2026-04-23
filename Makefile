# --- 1. Colors & Variables ---
RED    := $(shell tput -Txterm setaf 1)
GREEN  := $(shell tput -Txterm setaf 2)
CYAN   := $(shell tput -Txterm setaf 6)
RESET  := $(shell tput -Txterm sgr0)

GO_DIR=new
DOCKER_FILES=$(shell find . -name "Dockerfile*")
GECKODRIVER_BIN=$(shell command -v geckodriver 2>/dev/null)

ci-setup:
	@echo "$(CYAN)==> Starting containers in background...$(RESET)"
	docker compose up -d --build
	@echo "Waiting for webserver to be healthy..."
	sleep 30

ci-cleanup:
	@echo "$(CYAN)==> Tearing down Docker environment...$(RESET)"
	docker compose down -v

# ---------- Tests ---------------

# The Simulator: Captures output, fails fast, and reports errors
TIMEOUT_CMD := $(shell command -v timeout || command -v gtimeout)
test-sim:
	@echo "$(CYAN)==> Running simulator...$(RESET)"
	@python3 -m pip install requests --user -q
	@tmpfile=$$(mktemp); \
	if [ -z "$(TIMEOUT_CMD)" ]; then \
		echo "$(RED)Warning: 'timeout' command not found. Running without timeout...$(RESET)"; \
		python3 minitwit_simulator.py http://localhost:8080 >"$$tmpfile" 2>&1; \
	else \
		$(TIMEOUT_CMD) 500s python3 minitwit_simulator.py http://localhost:8080 >"$$tmpfile" 2>&1; \
	fi; \
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

wait-web:
	@echo "$(CYAN)==> Waiting for webserver readiness on /register...$(RESET)"
	@for i in $$(seq 1 45); do \
		status=$$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/register || true); \
		if [ "$$status" = "200" ]; then \
			echo "$(GREEN)Webserver is ready.$(RESET)"; \
			exit 0; \
		fi; \
		echo "waiting... ($$i/45) status=$$status"; \
		sleep 2; \
	done; \
	echo "$(RED)Webserver did not become ready in time.$(RESET)"; \
	exit 1

ui-e2e:
	@echo "$(CYAN)==> Running UI end-to-end tests...$(RESET)"
	@set -e; \
	GECKO_PATH="$${GECKODRIVER_PATH:-$(GECKODRIVER_BIN)}"; \
	if [ -z "$$GECKO_PATH" ]; then \
		echo "$(RED)geckodriver not found. Set GECKODRIVER_PATH or install geckodriver in PATH.$(RESET)"; \
		exit 1; \
	fi; \
	python3 -m pip install -r requirements-test.txt; \
	docker compose up -d --force-recreate dbserver webserver; \
	trap 'docker compose down -v' EXIT; \
	$(MAKE) wait-web; \
	MINITWIT_GUI_URL="$${MINITWIT_GUI_URL:-http://localhost:8080/register}" \
	MINITWIT_DB_URL="$${MINITWIT_DB_URL:-mongodb://localhost:27017/test}" \
	MINITWIT_HEADLESS="$${MINITWIT_HEADLESS:-1}" \
	GECKODRIVER_PATH="$$GECKO_PATH" \
	python3 -m pytest -v test_itu_minitwit_ui.py || { \
		echo "$(RED)UI E2E test failed; printing container logs...$(RESET)"; \
		docker compose logs --tail=120 webserver dbserver || true; \
		exit 1; \
	}

# --------- Execute tests --------------------------

# if one test file, still environment is cleaned up correctly
verify:
	@$(MAKE) ci-setup
	@$(MAKE) run-checks || (ret=$$?; $(MAKE) ci-cleanup; exit $$ret)
	@$(MAKE) ci-cleanup
	@echo "$(GREEN) All checks passed and environment cleaned!$(RESET)"

# Helper to group all checks together
run-checks: test-sim fmt lint-go lint-docker test

.PHONY: ci-setup test-sim fmt lint-go lint-docker test verify ci-cleanup run-checks wait-web ui-e2e