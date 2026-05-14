# Exam Expectations

This note summarizes what we expect the oral exam questions to focus on, based on `MSc_lecture_notes/exam_details.md`.

## Main Expectation

The exam will likely test whether we can explain and defend the decisions described in our report. The questions are not predefined. They will be based on our submitted report and the actual ITU-MiniTwit project.

That means every claim in the report should be something we can explain with:

- Why we made the decision.
- Which alternatives we considered or could have considered.
- What tradeoffs the decision created.
- How the decision affected maintainability, operations, deployment, security, or team workflow.
- What we would improve next.

## Likely Question Areas

### Technical Decisions

We should be ready to explain why we chose specific technologies and designs, for example:

- Docker and containerization.
- MongoDB and the persistence model.
- The CI/CD setup.
- The deployment setup.
- Monitoring and logging tools.
- Security hardening choices.
- Scaling and availability choices.

The important part is not just naming the tool, but explaining the reason for using it and its consequences.

### DevOps Reasoning

The examiners may challenge whether our way of working was actually DevOps-like.

We should be able to discuss:

- Automation in build, test, deployment, and infrastructure.
- Feedback loops from tests, monitoring, logging, and production behavior.
- Shared responsibility for development and operations.
- How quickly and safely changes can move from idea to production.
- How our process differs from a traditional development project.

### Tradeoffs and Consequences

The example questions in the exam details suggest that they may ask whether a decision was good or bad in a DevOps context.

We should prepare to discuss tradeoffs such as:

- Manual deployment versus automated deployment.
- Simpler architecture versus more scalable architecture.
- Fast implementation versus maintainability.
- Operational visibility versus system complexity.
- Security effort versus development speed.

### Team Organization

They may ask how the group was organized and whether knowledge was shared.

We should be ready to explain:

- How work was divided.
- Whether any team member became a single point of failure.
- How we reviewed, shared, or transferred knowledge.
- How future maintenance and refactoring could continue if one person is unavailable.
- What a DevOps advocate would say about our team organization.

### Report-Specific Claims

Anything written in the report is fair game.

Before the exam, we should review claims such as:

- "We automated deployment."
- "We monitor the system."
- "We aggregate logs."
- "We improved security."
- "We support scaling and availability."
- "We used CI/CD."
- "We refactored or evolved the system."

For each claim, we should know what we actually did, where it is implemented, and what evidence supports it.

### Individual Understanding

All group members will be in the exam room together, and questions will be distributed across the team.

Each person should therefore understand:

- The overall architecture.
- The CI/CD pipeline.
- Deployment flow.
- Monitoring and logging setup.
- Main operational risks.
- Key technical decisions.
- The largest lessons learned.

No one should only understand their own contribution.

## Preparation Checklist

- [ ] Review the final report and identify every major claim.
- [ ] For each claim, prepare a short explanation of why we did it.
- [ ] For each technical decision, prepare at least one alternative and one tradeoff.
- [ ] Review architecture, CI/CD, monitoring, logging, security, scaling, and infrastructure docs.
- [ ] Agree internally on the biggest lessons learned from evolution, operations, and maintenance.
- [ ] Make sure each team member can explain the full system at a high level.
- [ ] Prepare examples from commits, pull requests, issues, or decision records to support reflections.

## Short Summary

The exam is likely to emphasize explanation, justification, and reflection. We should be prepared to defend our project as a DevOps system, not just describe what we built.
