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

