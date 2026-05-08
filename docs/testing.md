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

