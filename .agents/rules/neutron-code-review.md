---
description: >-
  Neutron-specific code review guidelines: test conventions, API change policy,
  runtime dependency rules, ML2/OVN specifics, DB migration checks, stadium
  impact, and code rehoming to neutron-lib/ovsdbapp. Use when reviewing Neutron
  patches, Gerrit changes, or code contributions.
alwaysApply: false
---

# Neutron Code Review Guide

Neutron-specific review rules layered on top of the general OpenStack review
agent. Reference files (in the Neutron repository):
- `HACKING.rst`
- `doc/source/contributor/policies/code-reviews.rst`


## Dependencies

Reference: [AGENTS.md § Dependencies](../../AGENTS.md#dependencies)


## Neutron Hacking Checks

These are enforced by flake8 local plugins in `tox.ini`. Flag violations even
if the linter hasn't caught them yet (e.g. in comments or strings). The extension
list is provided in the `[flake8:local-plugins]extension` variable.


## Test Conventions

- All test classes must ultimately inherit from `neutron.tests.base.BaseTestCase`.
- Unit tests live under `neutron/tests/unit/` mirroring the package structure.
- Functional tests under `neutron/tests/functional/` (require env setup).
- Default test timeout: 180 seconds (`OS_TEST_TIMEOUT`).
- Test runner: `stestr` via `tox`.


## API Changes

Reference: [Tempest Testing – API Tests](doc/source/contributor/testing/tempest.rst#api-tests)

- Must have test coverage in `neutron-tempest-plugin` or Tempest.
- At minimum one API test; prefer both API and scenario tests.
- Scenario tests should cover real-world usage (e.g. instances using new networking, migration).
- Add negative test cases for error responses where appropriate.


## Runtime Dependency Changes

When a patch introduces a new runtime dependency (kernel, daemon, tool, rootwrap
filter, etc.):

1. Tag the commit message with `UpgradeImpact`.
2. Verify the dependency is available on supported platforms (Ubuntu LTS, CentOS).
3. Trigger experimental platform jobs via `check experimental` in Gerrit.
4. If a platform would break, require graceful fallback or `oslo.config` conditional.
5. Add a sanity check in `neutron/cmd/sanity/checks.py`.


## Stadium & Sub-project Impact

When renaming/removing methods, adding/removing positional args, or
renaming/removing constants:

1. Search [codesearch.openstack.org](https://codesearch.openstack.org) for usages.
2. Review non-voting and 3rd-party CI job results.
3. Coordinate with affected sub-projects to resolve breakage.


## Code Rehoming

When new methods, constants, or API definitions are added locally in Neutron,
check whether they belong in an external library instead:

- API definitions, constants, and shared utilities → `neutron-lib`.
- OVS/OVN OVSDB commands → `ovsdbapp`.


## ML2/OVN Specifics

- The contributor guide is in [contributor](doc/source/contributor/ovn/index.rst)
- OVS-related OVSDB commands live in the `ovsdbapp` library. Neutron also implements local
  commands defined in `neutron/plugins/ml2/drivers/ovn/mech_driver/ovsdb/api.py` and
  implemented in `neutron/plugins/ml2/drivers/ovn/mech_driver/ovsdb/impl_idl_ovn.py`.
- Check that all OVN commands are actually executed, by calling `execute(check_error=True)` or
  adding it to a transaction, inside a transaction context.
- When an OVN IDL event is attended by the Neutron API, check what worker will attend this event,
  based on the `HashRingManager` instance.
- For each OVN IDL command executed, check if that requires a database lock (`is_lock_contended`).


## DB Migrations

- Alembic migrations in [Alembic versions](neutron/db/migration/alembic_migrations/versions/).
- Check `check_migration` step in `tox -e pep8`.
- Migrations must be backward-compatible (online schema changes).
- Verify HEAD file consistency.
- Since [6af3801ac822d7825ddfbc62a5c1893605999b3e](https://review.opendev.org/c/openstack/neutron/+/950139),
  all alembic migrations must be idempotent. There is a functional test class,
  `TestMigrationsIdempotency`, that enforces this.


## Running Checks Locally

See [`HACKING.rst` § *Running Tests*](../../HACKING.rst#running-tests) for full details.
