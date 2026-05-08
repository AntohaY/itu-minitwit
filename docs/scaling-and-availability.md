# Scaling and Availability

## Coverage

This document should cover Session 09 scaling and availability work and connect it to deployment and infrastructure decisions.

It should explain:

- How Docker Swarm replicas are used.
- How rolling updates behave.
- How health checks support safer deployments.
- What downtime expectations exist.
- What failure modes are considered.
- What availability or SLO-style expectations the team has.

## Purpose

Use this page to explain how the system stays available during normal operation and deployment. Keep the mechanics of deploying a release in [Deployment](deployment.md).

## Scaling Model

Describe how the application scales.

Suggested topics:

- Number of replicas.
- Stateless application assumptions.
- Shared database dependency.
- Load balancing through Swarm.

## Rolling Updates

Explain update behavior.

Suggested topics:

- Update order.
- Parallelism.
- Delay between updates.
- Failure handling.
- Rollback behavior.

## Health Checks

Document health check behavior.

Suggested topics:

- Health endpoint.
- Docker or Swarm health check configuration.
- What health checks validate.
- What health checks do not validate.

## Availability Expectations

Describe realistic uptime expectations.

Suggested topics:

- Expected behavior during normal deployment.
- Expected behavior during node failure.
- Database as a dependency.
- Single points of failure.
- Manual recovery assumptions.

## Known Gaps

Examples:

- No formal SLO.
- Limited load testing.
- Database may be a bottleneck or single point of failure.
- Limited automated failover testing.

## README Material

- The project uses Swarm replicas, health checks, and rolling updates to improve availability.
- Current availability expectations and remaining risks are documented explicitly.

