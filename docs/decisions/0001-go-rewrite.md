# ADR 0001: Go Rewrite

## Status

Proposed

## Coverage

This decision should cover the rewrite and modernization work connected to Session 01 and Session 02.

It should explain:

- Why a rewrite or major restructuring was necessary.
- What alternatives were considered.
- Why Go was chosen, if applicable.
- What benefits and trade-offs the rewrite introduced.

## Context

Describe the inherited baseline and the constraints that motivated the rewrite.

## Decision

Document the final decision.

## Alternatives

- Keep the original implementation.
- Incrementally refactor the original implementation.
- Rewrite in another language or framework.

## Consequences

Describe positive and negative consequences.

=====

## Project Facts

- The current application is implemented in Go under `src/`.
- The HTTP stack uses `net/http` and `github.com/gorilla/mux`.
- The project still contains Python artifacts for testing/simulation, but the MiniTwit application runtime is Go.
- The Go implementation serves both browser UI and simulator API routes.
- The implementation uses Go templates under `src/templates/`.

### Evidence

- `src/main.go`
- `src/go.mod`
- `src/handlers/`
- `src/api/handlers.go`
- `src/templates/`
- Early migration/API history appears in PR #4 and PR #27: https://github.com/AntohaY/itu-minitwit/pull/4 and https://github.com/AntohaY/itu-minitwit/pull/27

### Needs Team Evidence

- The repo does not fully document the inherited baseline that was replaced or restructured.
- The team should add why Go was chosen over incremental refactoring or another language.
- The team should state the main tradeoff: Go simplified deployment as a compiled binary, but the current code still has handler-level database access and some security debt.
