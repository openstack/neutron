---
name: neutron-testing-patches
description: >-
  Create temporary DNM patches that stress-test Zuul CI jobs or individual
  tests by running them multiple times. Covers strategies for duplicating Zuul
  jobs, duplicating test classes/methods, modifying tox regexes, and repeating
  tests with stestr. Use when the user asks to create a testing patch,
  stress-test a CI job, run a test multiple times, or debug flaky tests.
---

# Neutron Testing Patches

Create temporary "Do Not Merge" (DNM) patches that stress-test CI jobs or
individual tests by running them multiple times. These patches are used to
reproduce intermittent failures or validate fixes.

## Important

- These patches are **never meant to be merged**. The commit message must
  start with `DNM ==` or `Testing patch for`.
- Always strip unrelated jobs/templates from `zuul.d/project.yaml` to reduce
  CI resource consumption.
- Remove the `gate:` pipeline entirely — only `check:` is needed.
- Remove the `templates:` section or keep only the minimal required template.

## Gathering Requirements

Before making changes, ask the user (use AskQuestion when available):

1. **Which strategy?**
   - A) Duplicate a Zuul CI job N times (parallel independent runs)
   - B) Duplicate a test class/method N times (more iterations per job)
   - C) Modify tox regex to run a specific class/test only
   - D) Repeat a single test N times sequentially in tox (stestr --combine)

2. **Target**: the job name, test class, or fully-qualified test path.
3. **Repetitions (N)**: how many times (default 10).
4. **Repository path**: which repo to modify.

## Strategy A: Duplicate a Zuul CI Job

Duplicate a parent job N times so Zuul runs N independent instances in
parallel.

### Pattern

In the project's `zuul.d/project.yaml` (or `zuul.d/base.yaml` if job
definitions live there):

1. **Define child jobs** (before the `- project:` block):

```yaml
- job:
    name: <parent-job-name>-01
    parent: <parent-job-name>
- job:
    name: <parent-job-name>-02
    parent: <parent-job-name>
# ... up to N
```

2. **Simplify the project section** — remove `templates:`, `gate:`, and all
   other jobs. Keep only the duplicated jobs under `check:`:

```yaml
- project:
    check:
      jobs:
        - <parent-job-name>-01
        - <parent-job-name>-02
        # ... up to N
```

### Numbering convention

- Use zero-padded two digits for N >= 10: `-01`, `-02`, ..., `-10`.
- Use single digits for N < 10: `-1`, `-2`, ..., `-5`.

### Example (N=5, job: neutron-tempest-plugin-ovn)

```yaml
- job:
    name: neutron-tempest-plugin-ovn-01
    parent: neutron-tempest-plugin-ovn
- job:
    name: neutron-tempest-plugin-ovn-02
    parent: neutron-tempest-plugin-ovn
- job:
    name: neutron-tempest-plugin-ovn-03
    parent: neutron-tempest-plugin-ovn
- job:
    name: neutron-tempest-plugin-ovn-04
    parent: neutron-tempest-plugin-ovn
- job:
    name: neutron-tempest-plugin-ovn-05
    parent: neutron-tempest-plugin-ovn

- project:
    check:
      jobs:
        - neutron-tempest-plugin-ovn-01
        - neutron-tempest-plugin-ovn-02
        - neutron-tempest-plugin-ovn-03
        - neutron-tempest-plugin-ovn-04
        - neutron-tempest-plugin-ovn-05
```

### Multiple parent jobs

When duplicating more than one parent job, define all child jobs (grouped
by parent) and list them all under `check:`:

```yaml
- job:
    name: job-a-1
    parent: job-a
- job:
    name: job-a-2
    parent: job-a
- job:
    name: job-b-1
    parent: job-b
- job:
    name: job-b-2
    parent: job-b

- project:
    check:
      jobs:
        - job-a-1
        - job-a-2
        - job-b-1
        - job-b-2
```

### Overriding the tempest test regex

When duplicating tempest-based jobs (jobs that inherit from
`devstack-tempest` or `tempest-multinode-full-py3`), you can restrict
which tests run by setting the `tempest_test_regex` variable in the
child job. This variable is defined in the `run-tempest` Ansible role
(`tempest/roles/run-tempest/defaults/main.yaml`) and consumed in its
task file (`tempest/roles/run-tempest/tasks/main.yaml`):

```
tox -e {{tox_envlist}} -- {{tempest_test_regex}} ...
```

**Critical: `tempest_test_regex` only works with `tox_envlist: all`.**

The `all` tox environment uses `{posargs}` as the `--regex` argument:

```
tempest run --regex {posargs:''}
```

Other tox environments (`integrated-network`, `multinode`, `smoke`,
etc.) have **hardcoded** `--regex` values and append `{posargs}` as
trailing extra arguments — `tempest_test_regex` is silently ignored
as a regex filter.

When the parent job uses a different `tox_envlist` (e.g.
`integrated-network`), **override it to `all`** in the child job:

```yaml
- job:
    name: neutron-ovs-tempest-multinode-full-1
    parent: neutron-ovs-tempest-multinode-full
    vars:
      tox_envlist: all
      tempest_test_regex: (tempest\.api\.compute\.admin\.test_live_migration\.LiveMigrationTest\.test_live_block_migration|tempest\.api\.compute\.admin\.test_live_migration\.LiveAutoBlockMigrationV225Test\.test_live_block_migration_paused)
- job:
    name: neutron-ovs-tempest-multinode-full-2
    parent: neutron-ovs-tempest-multinode-full
    vars:
      tox_envlist: all
      tempest_test_regex: (tempest\.api\.compute\.admin\.test_live_migration\.LiveMigrationTest\.test_live_block_migration|tempest\.api\.compute\.admin\.test_live_migration\.LiveAutoBlockMigrationV225Test\.test_live_block_migration_paused)

- project:
    check:
      jobs:
        - neutron-ovs-tempest-multinode-full-1
        - neutron-ovs-tempest-multinode-full-2
```

- Escape dots in fully-qualified test names with `\.`.
- Join multiple test paths with `|` inside a group `(...)`.
- Always pair `tempest_test_regex` with `tox_envlist: all`.

## Strategy B: Duplicate a Test Class or Method

Create empty subclasses or wrapper methods so the test runner picks them up
as additional test cases within the same job.

### Duplicating a class

Append numbered subclasses at the end of the test file:

```python
# NOTE: temporary CI debug duplication of ``OriginalTestClass`` to run
# the tests multiple times per job. Remove before merging.
class OriginalTestClass1(OriginalTestClass):
    pass


class OriginalTestClass2(OriginalTestClass):
    pass


class OriginalTestClass3(OriginalTestClass):
    pass
```

- Use a numbering suffix starting at 1.
- Add two blank lines between classes (PEP 8 top-level).
- Include the explanatory `# NOTE:` comment before the first duplicate.

### Duplicating a single method

If only one method needs repetition, create copies with numbered suffixes
inside the same class:

```python
# NOTE: temporary CI debug duplication of ``test_something``.
# Remove before merging.
def test_something_2(self):
    self.test_something()

def test_something_3(self):
    self.test_something()
```

### Combining with Strategy A

Often Strategy B is combined with Strategy A: duplicate the test class AND
reduce the zuul project.yaml to run only the relevant job (possibly also
duplicated).

## Strategy C: Modify tox Regex

Change the `test_regex` or filter in `tox.ini` to target a specific test
class or test method only.

### Adding a class to an existing regex

Append the class pattern to the existing `test_regex` variable:

```ini
# Before:
test_regex = .*ExistingPattern1.*|.*ExistingPattern2.*

# After (adding BGPExtensionTestCase):
test_regex = .*ExistingPattern1.*|.*ExistingPattern2.*|.*BGPExtensionTestCase.*
```

### Replacing the regex entirely

To run only one class or test:

```ini
test_regex = .*TargetTestClassName.*
```

Or for a specific method:

```ini
test_regex = .*TargetTestClassName.test_method_name.*
```

## Strategy D: Repeat a Single Test in tox (stestr --combine)

Replace the existing `commands` in the target tox environment to run one
test N times sequentially, combining results.

### Pattern

```ini
commands =
  bash {toxinidir}/tools/deploy_rootwrap.sh {toxinidir} {envdir}/etc {envdir}/bin
  stestr run <full.dotted.test.path>
  stestr run --combine <full.dotted.test.path>
  stestr run --combine <full.dotted.test.path>
  # ... repeat --combine line N-1 more times
```

- The **first** `stestr run` does NOT use `--combine` (initializes the DB).
- All **subsequent** calls use `--combine` to append results.
- Remove any `--slowest`, `--exclude-regex`, or `{posargs}` from the
  repeated lines.
- Keep setup commands (like `deploy_rootwrap.sh`) if they exist.

### Also strip zuul jobs

When using Strategy D, also strip `zuul.d/project.yaml` to keep only the
relevant tox-based job (e.g., `neutron-functional`):

```yaml
- project:
    check:
      jobs:
        - neutron-functional
```

### Example (50 repetitions)

```ini
commands =
  bash {toxinidir}/tools/deploy_rootwrap.sh {toxinidir} {envdir}/etc {envdir}/bin
  stestr run neutron.tests.functional.services.ovn_l3.test_plugin.TestRouter.test_method
  stestr run --combine neutron.tests.functional.services.ovn_l3.test_plugin.TestRouter.test_method
  stestr run --combine neutron.tests.functional.services.ovn_l3.test_plugin.TestRouter.test_method
  # ... (repeat --combine line 48 more times, total 50 executions)
```

## Commit Message

### Title

Use one of these title formats:

- `DNM == Test ``<test or job description>`` ` — when stress-testing a
  specific test or job.
- `Testing patch for <change-number>` — when validating another CL.

### Body (optional)

If referencing another change or bug, add a link in the body following the
link format from [git-commit-messages.md](../../rules/git-commit-messages.md).

### Trailers

Follow [git-commit-messages.md](../../rules/git-commit-messages.md) for all
trailer conventions (Assisted-By, Signed-off-by, Change-Id, Related-Bug,
etc.).

## Workflow Checklist

1. Identify the repository and locate `zuul.d/project.yaml` and/or `tox.ini`.
2. Read the current file contents.
3. Ask the user which strategy (A/B/C/D) and parameters.
4. Apply the changes following the patterns above.
5. Verify YAML syntax (2-space indent, no tabs) for zuul files.
6. Present a summary of changes to the user.
