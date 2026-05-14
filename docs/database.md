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

=====

## Project Facts

### What We Implemented

- MongoDB is the database used by both the web application and the Discord bot.
- The Go application connects through the official MongoDB Go driver.
- `MONGO_URI` is read from the environment.
- If `MONGO_URI` is not set, the application falls back to `mongodb://dbserver:27017`.
- `ResolveClientDB` currently selects database name `test` directly with `dbClient.Database("test")`.
- The main collections are `user`, `message`, and `follower`.
- User documents include username, email, `pw`, and `hashedpw`.
- Message documents include `author_id`, `text`, `pub_date`, and `flagged`.
- Follower documents include `who_id` and `whom_id`.
- Startup creates indexes for:
  - unique `user.username`
  - unique follower relation on `who_id` and `whom_id`
  - follower lookup by `who_id`
  - public timeline lookup by `flagged` and `pub_date`
  - user timeline lookup by `author_id`, `flagged`, and `pub_date`
- PR #78 moved production deployment toward a DigitalOcean managed MongoDB URI assembled from GitHub Secrets: https://github.com/AntohaY/itu-minitwit/pull/78.

### Evidence in the Repository

- `src/db_setup/ResolveClientDB.go`
- `src/types/User.go`
- `src/types/Message.go`
- `src/api/handlers.go`
- `src/handlers/`
- `docker-compose.yml`
- `remote_files/docker-stack.yml`
- `src/bot/main.go`

### Known Gaps / Needs Team Evidence

- Passwords are currently stored and compared as plain strings. `CheckPasswordHash` contains a TODO for proper password hashing. This is a security and maintenance limitation.
- `docker-compose.yml` sets `MONGO_INITDB_DATABASE=minitwit`, but the Go code always uses database `test`. The team should verify whether this is intentional.
- Production uses an external MongoDB URI in `continous-deployment.yml`, and PR #78 shows the move to DigitalOcean managed MongoDB. The repo still cannot prove the current database health, backup policy, or high-availability settings.
- No automated migration system is visible in the repository. Index creation happens at application startup.

### Oral Exam Answer

MongoDB stores users, messages, and follow relationships. The application ensures important indexes at startup, including unique usernames and unique follow pairs. The main tradeoff is simplicity: handlers use MongoDB directly and there is no migration framework. A clear remaining security issue is that passwords are not properly hashed yet.
