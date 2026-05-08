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

