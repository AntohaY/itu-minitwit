# Old makeFile

#init:
#	python -c"from minitwit import init_db; init_db()"

#build:
#	gcc flag_tool.c -l sqlite3 -o flag_tool

#clean:
#	rm flag_tool

# new makeFile

GREEN  := $(shell tput -Txterm setaf 2)
CYAN   := $(shell tput -Txterm setaf 6)
RESET  := $(shell tput -Txterm sgr0)

GO_DIR=new
DOCKER_FILES=$(shell find . -name "Dockerfile*")

fmt:
	@echo "$(CYAN)==> Formatting Go code...$(RESET)"
	cd $(GO_DIR) && go fmt ./...

# 2. Run Go Static Analysis (Staticcheck)
lint-go:
	@echo "$(CYAN)==> Running staticcheck...$(RESET)"
	cd $(GO_DIR) && golangci-lint run ./...

# 3. Run Hadolint on all Dockerfiles found in the repo
lint-docker:
	@echo "$(CYAN)==> Running Hadolint on all Dockerfiles...$(RESET)"
	@$(foreach file,$(DOCKER_FILES), \
		echo "Linting $(file)"; \
		docker run --rm -i hadolint/hadolint < $(file) || exit 1; \
	)

# 4. Run Go unit tests
test:
	@echo "$(CYAN)==> Running Go tests...$(RESET)"
	cd $(GO_DIR) && go test -v ./...

# 5. The "Mega Check" - run everything at once
verify: fmt lint-go lint-docker test
	@echo "$(GREEN) All local checks passed! $(RESET)"

.PHONY: init build clean fmt lint-go lint-docker test verify