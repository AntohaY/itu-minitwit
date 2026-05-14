# API

## Coverage

This document should cover Session 03 and Session 04 simulator API work. It should explain how the application implements the required API behavior and how the implementation relates to `swagger3.json`.

It should explain:

- Which API endpoints are implemented.
- How the implementation follows the Swagger/OpenAPI specification.
- How simulator authentication works.
- How request and response formats are handled.
- How API errors are represented.
- Which tests or scripts verify API compatibility.

## Purpose

Use this page to document the API contract. The target reader should understand how the simulator interacts with the application and how future API changes should be validated.

## API Specification

Describe the role of `swagger3.json`.

Suggested topics:

- Which routes are defined by the spec.
- Whether the implementation follows the spec exactly or has known deviations.
- How the spec is used during testing or development.

## Authentication

Document how simulator or API authentication works.

Suggested topics:

- Required headers.
- Shared secrets or tokens.
- Unauthorized request behavior.
- Where secrets are configured.

## Endpoints

List the supported endpoints and their responsibilities.

Suggested areas:

- Latest command endpoint.
- Register user.
- Follow and unfollow.
- Public timeline.
- User timeline.
- Message creation.

## Error Handling

Explain API error behavior.

Suggested topics:

- Validation errors.
- Authentication failures.
- Missing resources.
- Database failures.

## API Testing

Document how API compatibility is tested.

Suggested references:

- Simulator scripts.
- Shell-based route tests.
- CI jobs that run API tests.

## README Material

- The project exposes a simulator-compatible API defined by `swagger3.json`.
- API behavior is verified through local scripts and CI checks.

=====

## Project Facts

### What We Implemented

- The application is a Go HTTP service using `github.com/gorilla/mux`.
- API routes are registered in `src/main.go`.
- The implemented simulator-facing routes are:
  - `GET /latest`
  - `POST /register`
  - `GET /msgs`
  - `GET /msgs/{username}`
  - `POST /msgs/{username}`
  - `GET /fllws/{username}`
  - `POST /fllws/{username}`
- The route set matches the main paths defined in `swagger3.json`.
- `GET /msgs`, `GET/POST /msgs/{username}`, and `GET/POST /fllws/{username}` are protected by API Basic Auth in `src/api/handlers.go`.
- The simulator Basic Auth credentials are hard-coded as `simulator` / `super_safe!`.
- `POST /register` is not wrapped with the API auth middleware in `src/main.go`, even though the smoke-test script can send auth credentials to it.
- `GET /latest` returns an in-memory latest command value. The value starts at `-1` and is updated from the `?latest=` query parameter when API handlers call `updateLatest`.
- API data is stored in MongoDB collections named `user`, `message`, and `follower`.
- API responses use JSON for normal data responses and most validation/authentication errors.

### Evidence in the Repository

- `src/main.go`: route registration and `/metrics` exposure.
- `src/api/handlers.go`: API handlers, Basic Auth middleware, latest-command handling, response formats.
- `swagger3.json`: expected API contract.
- `test-api-routes.sh`: read-only and write-mode smoke tests for deployed or local API endpoints.
- `register_test.py`: small Python test script for registration and follow behavior.
- `Makefile`: runs `minitwit_simulator.py` through `make test-sim`.

### Known Gaps / Needs Team Evidence

- Continuous Integration run `#84` passed on PR #154's merge commit, and the CI path runs `make verify`, which includes `minitwit_simulator.py`: https://github.com/AntohaY/itu-minitwit/actions/runs/25637564257.
- PR #139 added `test-api-routes.sh`, and PR #154 expanded API smoke coverage with registration edge cases: https://github.com/AntohaY/itu-minitwit/pull/139 and https://github.com/AntohaY/itu-minitwit/pull/154.
- Exact Swagger/OpenAPI compliance should still not be overclaimed unless checked endpoint-by-endpoint against `swagger3.json`.
- The Basic Auth credentials are hard-coded in code, so the report should treat this as a security limitation.
- Some error paths return only an HTTP status without a JSON body, for example some missing-resource cases. If the report claims fully structured error responses, this needs verification against `swagger3.json`.
- The `/latest` value is in memory, so it resets on process restart and is not shared across replicas. This matters in production because the remote stack runs multiple web replicas.

### Oral Exam Answer

The project implements the MiniTwit simulator API in the same Go service as the browser UI. Gorilla Mux routes requests to JSON API handlers backed by MongoDB, and protected simulator routes use Basic Auth. API compatibility is checked with the simulator and smoke-test scripts, but we should be honest that some behavior, such as the in-memory `/latest` value and hard-coded simulator credentials, remains a limitation.
