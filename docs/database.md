# Database

## Coverage

This document should cover Session 05 and explain the database design and persistence abstraction used by the project.

It should explain:

- Why MongoDB is used.
- Which collections and data shapes exist.
- How database access is separated from HTTP handlers.
- How connections are configured and managed.
- Which indexes, constraints, or consistency assumptions matter.
- Known limitations and future data-model improvements.

## Purpose

Use this page to document persistence decisions. The main question this page should answer is: "How does the application store and retrieve data without embedding database logic directly into request handlers?"

## Database Choice

Describe why the project uses MongoDB.

Suggested topics:

- Fit with current data model.
- Managed database or production hosting considerations.
- Trade-offs compared with the original storage approach.
- Operational consequences.

## Data Model

Document the main collections and fields.

Suggested collections:

- Users.
- Messages.
- Followers or relationships.
- Latest simulator command state, if stored.

## Persistence Boundary

Explain where database access lives in the codebase.

Suggested topics:

- Repository functions.
- Handler-to-repository flow.
- Why handlers should not contain raw database logic.
- How this improves testability and future migrations.

## Connection Management

Document how the application connects to MongoDB.

Suggested topics:

- Environment variables.
- Connection strings.
- Local vs production configuration.
- Error handling and startup behavior.

## Known Gaps

Examples:

- Missing indexes.
- Weak schema validation.
- Limited migration strategy.
- Possible consistency issues under concurrency.

## README Material

- The project uses MongoDB for persistence.
- Database access is intended to be isolated behind a persistence boundary rather than spread through handlers.

