# Testing

## Coverage

This document should cover Session 07 testing work and connect to Session 03 API compliance testing.

It should explain:

- Which tests exist.
- How to run tests locally.
- How tests are executed in CI.
- What risks the current tests cover.
- What important gaps remain.
- How UI, API, unit, and integration-style tests differ in this project.

## Purpose

Use this page to document confidence in the system. It should help a team member understand what is tested before changing application behavior.

## Test Types

Document the categories of tests.

Suggested categories:

- Unit tests.
- API route tests.
- Simulator-related tests.
- UI tests.
- Manual smoke tests.

## Running Tests Locally

List common commands.

Suggested references:

- `requirements-test.txt`
- `test_itu_minitwit_ui.py`
- `test-api-routes.sh`
- `register_test.py`

## CI Test Execution

Describe how tests run in GitHub Actions.

Suggested topics:

- Which workflow runs tests.
- Required services or environment variables.
- Which failures block merge or deployment.

## Coverage and Gaps

Document what is covered and what is missing.

Examples:

- Strong coverage of core user flows.
- Limited database failure testing.
- Limited load or concurrency testing.
- Manual checks still needed after deployment.

## README Material

- The project includes automated tests for important MiniTwit behavior.
- Tests are run locally and in CI to support safe changes.

=====

## Project Facts

### Test Types

- Simulator testing is run through `minitwit_simulator.py`.
- API smoke testing is available through `test-api-routes.sh`.
- A small Python API test script exists in `register_test.py`.
- UI and end-to-end tests are implemented in `test_itu_minitwit_ui.py` using Selenium, Firefox, Geckodriver, Pytest, and PyMongo.
- Go test execution is included through `go test -v ./...`.
- Dockerfile linting is included through Hadolint.
- Go lint/static analysis is included through `golangci-lint`.
- Formatting is checked by running `go fmt ./...`.

### UI/E2E Coverage

PR #131 added the Selenium/Pytest UI/E2E suite and connected it to GitHub Actions: https://github.com/AntohaY/itu-minitwit/pull/131.

`test_itu_minitwit_ui.py` covers:

- Registering a user through the GUI.
- Verifying a GUI registration creates a MongoDB user.
- Login and logout flow.
- Duplicate username validation.
- Posting a message and checking the database.
- Following and unfollowing another user and checking the database relation.

### CI Execution

- `static-analysis.yml` runs `make verify`.
- `make verify` starts Docker Compose, runs `make run-checks`, and tears the environment down.
- `make run-checks` runs simulator, formatting, Go linting, Dockerfile linting, and Go tests.
- The `ui-e2e` GitHub Actions job runs after `verify`.
- The `ui-e2e` job starts the local services and runs the Selenium/Pytest suite.

### Evidence in the Repository

- `Makefile`
- `.github/workflows/static-analysis.yml`
- `minitwit_simulator.py`
- `minitwit_scenario.csv`
- `test-api-routes.sh`
- `register_test.py`
- `test_itu_minitwit_ui.py`
- `requirements-test.txt`
- `docker-compose.yml`

### Known Gaps / Needs Team Evidence

- No Go `*_test.go` files are visible under `src`, so Go unit-test coverage appears limited or absent.
- Continuous Integration run `#84` passed on PR #154's merge commit: https://github.com/AntohaY/itu-minitwit/actions/runs/25637564257.
- No load, stress, or failover tests are visible.
- Database failure and concurrency scenarios are only lightly covered.
- `test-api-routes.sh` is useful and was added in PR #139, then expanded in PR #154, but the workflow still does not clearly call that script automatically.

### Oral Exam Answer

The test strategy combines simulator testing, static checks, Dockerfile linting, API smoke tests, and Selenium/Pytest UI end-to-end tests. The strongest behavioral tests are the simulator and UI/E2E tests. The main gap is that there are no visible Go unit tests and no load or failover testing, so the test suite gives useful confidence but not complete coverage.
