# ADR 0003: Database Choice

## Status

Proposed

## Coverage

This decision should cover Session 05 database and persistence work.

It should explain:

- Why MongoDB was chosen.
- How the database choice affects the application data model.
- What alternatives were considered.
- What trade-offs exist around operations, consistency, and testing.

## Context

Describe the persistence requirements and original data storage approach.

## Decision

Document the selected database approach.

## Alternatives

- Keep the original database.
- Use PostgreSQL.
- Use another managed database.

## Consequences

Describe positive and negative consequences.

=====

## Project Facts

- The project uses MongoDB.
- The Go service connects through `go.mongodb.org/mongo-driver`.
- The application stores users, messages, and follow relations in MongoDB collections.
- The production deployment constructs a DigitalOcean MongoDB connection string in the deployment workflow.
- The application creates important indexes at startup.

### Evidence

- `src/db_setup/ResolveClientDB.go`
- `src/api/handlers.go`
- `src/handlers/`
- `.github/workflows/continous-deployment.yml`
- `docker-compose.yml`
- PR #78 moved production deployment toward a DigitalOcean managed MongoDB URI: https://github.com/AntohaY/itu-minitwit/pull/78

### Needs Team Evidence

- The team should document why MongoDB was chosen over PostgreSQL or the original storage approach.
- The code currently forces database name `test`, so the team should clarify whether that is intentional.
- The team should document production backup, availability, and operational ownership for the database if known.
