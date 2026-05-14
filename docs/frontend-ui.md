# Frontend UI

## Coverage

This document should cover the user-facing MiniTwit web interface and any UI behavior tested by the project.

It should explain:

- Which pages and user flows exist.
- How login, registration, timelines, following, unfollowing, and message posting behave.
- How UI behavior relates to backend API and database state.
- Which UI tests exist and what they verify.
- Known UI limitations or future improvements.

## Purpose

Use this page to document the browser-facing experience. Keep simulator-specific API behavior in [API](api.md) and test execution details in [Testing](testing.md).

## User Flows

Document the main UI workflows.

Suggested flows:

- Register a new user.
- Log in and log out.
- View public timeline.
- View personal timeline.
- Post a message.
- Follow or unfollow another user.

## Pages and Templates

List the main UI pages and templates.

Suggested items:

- Public timeline.
- User timeline.
- Login page.
- Registration page.
- Message form.
- Error or empty states.

## UI Testing

Describe which UI behavior is covered by automated tests.

Suggested references:

- `test_itu_minitwit_ui.py`
- Browser or HTML-level assertions.
- Known manual checks.

## Known Gaps

Examples:

- Limited responsive design documentation.
- Limited accessibility checks.
- Missing browser compatibility notes.

## README Material

- The project preserves the core MiniTwit user flows through a web UI.
- UI behavior is covered by automated tests where practical.

=====

## Project Facts

### What We Implemented

- The browser UI is served by the Go web application on the same port as the API.
- UI templates are Go HTML templates under `src/templates/`.
- Static assets are served from `/static/`.
- Styling uses Bootstrap from a CDN plus project CSS in `src/static/style.css`.
- The implemented UI routes include `/`, `/login`, `/register_user`, `/timeline`, `/logout`, `/user/{username}`, `/user/follow/{username}`, `/user/unfollow/{username}`, `/add_message`, and `/ping`.
- The UI supports registration, login, logout, public timeline, personal timeline, user timelines, follow/unfollow, and posting messages.
- Sessions use Gorilla sessions with a cookie store.
- The session cookie is configured as `HttpOnly` and `Secure`.
- The 404 page is rendered from `src/templates/404.html`.

### Evidence in the Repository

- `src/main.go`
- `src/templates/layout.html`
- `src/templates/login.html`
- `src/templates/register.html`
- `src/templates/timeline.html`
- `src/templates/404.html`
- `src/static/style.css`
- `src/handlers/auth_handlers.go`
- `src/handlers/timeline_handlers.go`
- `src/handlers/follow_handlers.go`
- `src/handlers/message_handlers.go`
- `test_itu_minitwit_ui.py`
- PR #131 added Selenium/Pytest UI/E2E coverage for registration, login/logout, duplicate username validation, posting, and follow/unfollow flows: https://github.com/AntohaY/itu-minitwit/pull/131.

### Known Gaps / Needs Team Evidence

- `src/templates/timeline.html` contains visible placeholder/joke text such as `Public Timeline Really really good` and `SHREEEEEEEK`; the team should decide whether to keep or polish this before final submission.
- Password handling is not secure because credentials are stored as plain strings.
- The app uses Bootstrap from a CDN, so frontend rendering depends on external CDN availability.
- Need screenshots if the report wants to show the UI; automated flow coverage is evidenced by PR #131, but screenshots are still useful for report presentation.

### Oral Exam Answer

The UI preserves the MiniTwit workflows through Go templates and standard web forms. It supports account registration, login/logout, timelines, posting, and follow/unfollow behavior, with Selenium/Pytest tests covering important user flows. The UI is functional, but some visible placeholder text and weak password handling should be treated as known limitations.
