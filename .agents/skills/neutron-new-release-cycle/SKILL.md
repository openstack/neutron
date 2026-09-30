---
name: neutron-new-release-cycle
description: >-
  Guides Neutron developers and release liaisons through the cycle-boundary
  patches required when a series is released and the next one starts: OVS/OVN
  docs, stable-branch CI, DB milestones, SLURP jobs, spec folders, and cycle
  highlights. Use when cutting RC1, after stable branch creation, opening a new
  development series on master, or preparing final Neutron releases.
---

# Neutron New Release Cycle

Workflow for **Neutron code people** (PTL, release liaison, core devs, stadium
subproject owners) at a major cycle boundary.

## Before You Start

Resolve names from `/opt/stack/releases/data/series_status.yaml`:

- `RELEASE_ID` — e.g. `2026.1`
- `CODENAME` — e.g. `gazpacho`
- `STABLE_BRANCH` — e.g. `stable/2026.1`
- `NEXT_RELEASE_ID` — e.g. `2026.2`
- `NEXT_CODENAME` — e.g. `hibiscus`

Read the previous cycle's patches in Gerrit and **copy the pattern**, substituting
series names. Never guess branch names or version numbers.

**Related skills:**

- `openstack-new-release` — individual deliverable version bumps in
  `openstack/releases` (RC1, milestones, finals)
- Cycle highlights content — separate skill (not yet available); Phase 5 below
  covers the deliverable YAML edit only

**Stadium repos** (all need stable-branch `.gitreview` / constraints patches):
neutron, neutron-lib, neutron-tempest-plugin, python-neutronclient,
neutron-fwaas, neutron-fwaas-dashboard, neutron-vpnaas,
neutron-vpnaas-dashboard, neutron-dynamic-routing, networking-sfc,
networking-bgpvpn, networking-bagpipe, tap-as-a-service, ovsdbapp, os-ken,
ovn-bgp-agent, ovn-octavia-provider.

Only commit when the user explicitly asks. Use OpenStack git conventions for
commit messages.

## Checklist

```
Neutron cycle boundary:
- [ ] Phase 1: OVS/OVN minimum version table
- [ ] Phase 3: releases patches approved; stable .gitreview + tox-constraints merged
- [ ] Phase 3.a: neutron-tempest-plugin stable jobs
- [ ] Phase 3.b: neutron + neutron-lib tempest job switch; drop *-master jobs
- [ ] Phase 3.c: Grafana dashboards (project-config)
- [ ] Phase 4.a: DB branch + milestones + SLURP toggle (neutron master)
- [ ] Phase 4.b: neutron-specs folder for next series
- [ ] Phase 4.c: testing runtime Zuul overrides (neutron + subprojects)
- [ ] Phase 5: cycle highlights in openstack/releases
```

---

## Phase 1 — Pre-RC1 (`master`)

**When:** Before RC1, while `master` still targets the series being released.

### Patch: Update OVS/OVN minimum version table

**Reference:** [967816](https://review.opendev.org/c/openstack/neutron/+/967816)
(initial table), [998781](https://review.opendev.org/c/openstack/neutron/+/998781)
(2026.1 row)

- **Repo:** `openstack/neutron`
- **Branch:** `master`
- **File:** `doc/source/install/ovs-ovn-requirements.rst`

**How to implement:**

1. Read CI variables for the series being released (`OVS_BRANCH`, `OVN_BRANCH`
   from Zuul job vars or devstack) — use the **base** tempest job versions, not
   grenade/rally variants.
2. Add a **new row at the top** of the list-table (newest release first):
   - OpenStack Release: `<RELEASE_ID> (<codename>)`
   - Neutron Release: major version from deliverable YAML (e.g. `28.0` → `28.0`)
   - `OVS_BRANCH` and `OVN_BRANCH` values used in CI
3. Keep older rows unchanged.
4. Run `tox -e docs` or at least verify RST builds.

**Commit title:** `Update \`\`OVS/OVN Minimum Requirement Matrix\`\` with <RELEASE_ID>`

---

## Phase 2 — *(no standalone phase)*

RC1 and final release patches live in `openstack/releases`. See Phase 3
prerequisite and the `openstack-new-release` skill.

---

## Phase 3 — Stable branch configuration

**When:** After the release team creates `STABLE_BRANCH`.

### Prerequisite: releases patches approved and merged

Before any Phase 3 repo work:

1. PTL / release liaison proposes RC1 patches in `openstack/releases` — one per
   deliverable (neutron + each stadium project). Use the `openstack-new-release`
   skill; hash must be the **merge commit**.
2. Neutron release liaison reviews (+1) stadium release patches.
3. Wait until **all** required releases patches are merged and the release team
   has created `STABLE_BRANCH`.

Do not start stable-branch configuration until this is done.

### All stadium projects: `.gitreview` and `TOX_CONSTRAINTS_FILE`

**No step-by-step patch here** — confirm these two patches are **merged on
`STABLE_BRANCH` for every stadium repo** (often auto-proposed by the release
bot; subproject owners verify):

- **`Update .gitreview for stable/<RELEASE_ID>`** — add
  `defaultbranch=stable/<RELEASE_ID>` under `[gerrit]`
- **`Update TOX_CONSTRAINTS_FILE for stable/<RELEASE_ID>`** — point default
  constraints URL to
  `https://releases.openstack.org/constraints/upper/stable/<RELEASE_ID>` in
  `tox.ini` (and `pyproject.toml` if present)

Also expect `Update master for stable/<RELEASE_ID>` (reno branch metadata) on the
same stable branch. If missing for your repo, copy from the previous cycle's
Gerrit patch for that project.

**Example triplet (Gazpacho / stable/2026.1):**
- [980118](https://review.opendev.org/c/openstack/neutron/+/980118)
- [980119](https://review.opendev.org/c/openstack/neutron/+/980119)
- [980120](https://review.opendev.org/c/openstack/neutron/+/980120)

---

### Phase 3.a — `neutron-tempest-plugin` stable jobs

**Reference:** [980321](https://review.opendev.org/c/openstack/neutron-tempest-plugin/+/980321)

- **Repo:** `openstack/neutron-tempest-plugin`
- **Branch:** `STABLE_BRANCH` (and mirror job defs used from master templates)

**How to implement:**

1. Copy the previous series job file (e.g. `zuul.d/2025_2_jobs.yaml`) to
   `zuul.d/<YYYY>_<N>_jobs.yaml` (underscores: `2026_1_jobs.yaml`).
2. In every job in the new file:
   - Rename jobs: suffix `-<YYYY>-<N>` (e.g. `-2026-1`)
   - Set `override-checkout: stable/<RELEASE_ID>`
   - Copy `network_api_extensions_*` and `network_available_features` from
     devstack stable config for that series — match the previous cycle's patch
3. Add a `project-template` `neutron-tempest-plugin-jobs-<YYYY>-<N>` in
   `zuul.d/project.yaml` listing the new jobs (check/gate/experimental).
4. Register the template under the `project:` `templates:` list.
5. Add stable-series job variants for stadium plugins (fwaas, vpnaas, sfc, etc.)
   following the previous cycle's diff in `zuul.d/project.yaml`.

**Commit title:** `Add <RELEASE_ID> (<Codename>) stable jobs`

---

### Phase 3.b — `neutron` and `neutron-lib` tempest jobs (stable branch only)

**References:**

- [981131](https://review.opendev.org/c/openstack/neutron/+/981131) — **neutron:**
  switch to branched tempest-plugin jobs
- [981203](https://review.opendev.org/c/openstack/neutron-lib/+/981203) —
  **neutron-lib:** same

- **Branch:** `STABLE_BRANCH` only — subject line includes series, e.g.
  `[2026.1 only]`

**How to implement (981131 / 981203):**

1. Open the previous cycle's stable-branch patch in Gerrit for the same repo.
2. In `zuul.d/project.yaml` (and related yaml), replace master tempest job
   templates with `neutron-tempest-plugin-jobs-<YYYY>-<N>`.
3. Ensure jobs use `override-checkout: stable/<RELEASE_ID>` for
   neutron-tempest-plugin (via the branched job definitions from Phase 3.a).
4. Limit the patch to the stable branch using Gerrit topic or clear subject
   `[<RELEASE_ID> only]`.

**Commit title:** `[<RELEASE_ID> only] Switch to <RELEASE_ID> neutron-tempest-plugin jobs`

---

### Phase 3.c — Grafana dashboards (`project-config`)

**Reference:** [757102](https://review.opendev.org/c/openstack/project-config/+/757102)

- **Repo:** `openstack/project-config`
- **Branch:** `master`
- **Who:** usually infra/PTL — Neutron team tracks completion

**How to implement:**

1. Find Grafana dashboard JSON under `grafana/` (or equivalent) for neutron
   stable branches.
2. Add or update dashboard entries for the new `STABLE_BRANCH` following the
   previous cycle's diff.
3. Copy the file naming pattern from the prior release patch in Gerrit.

Neutron developers typically **review and nag**, not author — unless you are
the release liaison with project-config access.

---

## Phase 4 — Open next series on `master`

**When:** `STABLE_BRANCH` exists; `master` targets `NEXT_RELEASE_ID`.

### Phase 4.a — `neutron` DB branch, milestones, and SLURP

Apply as **one or two patches** on `master`. Use the references as templates.

#### [980303](https://review.opendev.org/c/openstack/neutron/+/980303) — Open new DB branch

- **Repo:** `openstack/neutron`
- **Branch:** `master`

**How to implement:**

1. Create directory
   `neutron/db/migration/alembic_migrations/versions/<NEXT_RELEASE_ID>/expand/`
   (and `contract/` if the cycle uses contract scripts — follow previous cycle).
2. Add `RELEASE_<YYYY>_<N>` constant in `neutron/db/migration/__init__.py`:
   ```python
   RELEASE_2026_2 = '2026.2'
   ```
3. Set `CURRENT_RELEASE = migration.RELEASE_<NEXT>` in
   `neutron/db/migration/cli.py`.
4. Append `migration.RELEASE_<NEXT>` to the `RELEASES` tuple in `cli.py`.
5. Do **not** add the new series to `NEUTRON_MILESTONES` yet (see 944804).
6. First migration in the new expand branch chains from the last expand head of
   the previous series.

**Commit title:** `Open the <NEXT_RELEASE_ID> (<Codename>) DB branch`

#### [944804](https://review.opendev.org/c/openstack/neutron/+/944804) — Tag released series milestone

- **When:** at cycle boundary — tag the **just-released** series
- **Branch:** `master`

**How to implement:**

1. On the **last alembic expand script** of the released series (under
   `versions/<RELEASE_ID>/expand/`), set:
   ```python
   neutron_milestone = [migration.RELEASE_<YYYY>_<N>]
   ```
2. Append `RELEASE_<released>` to `NEUTRON_MILESTONES` in
   `neutron/db/migration/__init__.py` (remove the "do not add" comment for
   that entry only).
3. Often combined with 980303 in practice — if split, land milestone tagging
   before or with the new branch patch.

**Commit title:** `Open the <RELEASE_ID> (<Codename>) DB branch` (may include
milestone tagging) or `Add missing Neutron milestones`

#### [962240](https://review.opendev.org/c/openstack/neutron/+/962240) — Enable SLURP (`.1` series)

**Use when** `NEXT_RELEASE_ID` ends in `.1` (SLURP release — e.g. 2026.1,
2027.1). Check `slurp: yes` in `series_status.yaml`.

**How to implement:**

1. In `zuul.d/job-templates.yaml`, template `neutron-skip-level-jobs`:
   - **Uncomment** `check:` jobs for skip-level grenade jobs
   - **Remove** those jobs from `periodic:` and `experimental:` (or leave
     experimental only — copy 962240 exactly)
2. In `zuul.d/grenade.yaml`, jobs `neutron-*-grenade-multinode-skip-level`:
   - Set `grenade_from_branch: stable/<PREVIOUS_SLURP_RELEASE>` (the `.1`
     release two cycles back, e.g. master is 2026.2 → use `stable/2025.2` when
     opening 2026.2; when master is 2027.1 → use `stable/2026.1`)
   - Update comments explaining the skip-level target

**Commit title:** `Bump skip-level lower version to stable/<branch>`

#### [982005](https://review.opendev.org/c/openstack/neutron/+/982005) — Disable SLURP (`.2` series)

**Use when** `NEXT_RELEASE_ID` ends in `.2` (non-SLURP — e.g. 2026.2).

**How to implement:**

1. In `neutron-skip-level-jobs` template:
   - **Comment out** `check:` skip-level jobs
   - Keep jobs under `periodic:` and `experimental:` only
2. Keep `grenade_from_branch` pointing at the correct stable branch (same
   logic as 962240 — read comments in `grenade.yaml`).

**Commit title:** `Disable skip-level jobs in check queue`

**Rule:** `.1` → 962240 pattern; `.2` → 982005 pattern. Never enable both.

---

### Phase 4.b — `neutron-specs` folder for next series

**Reference:** [980305](https://review.opendev.org/c/openstack/neutron-specs/+/980305)

- **Repo:** `openstack/neutron-specs`
- **Branch:** `master`

**How to implement:**

1. Create `specs/<NEXT_RELEASE_ID>/index.rst`:
   ```rst
   ===========
   <NEXT_RELEASE_ID>
   ===========

   .. toctree::
      :glob:
      :maxdepth: 1

      *
   ```
2. Mirror under `doc/source/specs/<NEXT_RELEASE_ID>/index.rst` (same content).
3. Add `specs/<NEXT_RELEASE_ID>/index` to `doc/source/index.rst` toctree near
   the top (newest first).
4. Copy `specs/<NEXT_RELEASE_ID>/` layout from the previous cycle's Gerrit diff.

**Commit title:** `Spec folder for <NEXT_RELEASE_ID> (<Codename>) cycle`

---

### Phase 4.c — Testing runtime Zuul overrides

**Reference:** [985322](https://review.opendev.org/c/openstack/neutron/+/985322)

- **Repo:** `openstack/neutron` (repeat in neutron-lib + stadium repos)
- **Branch:** `master`
- **When:** governance adds/removes a Python version for the new series

**How to implement:**

1. Read the governance testing-runtime patch for `NEXT_RELEASE_ID` (e.g.
   `openstack/governance` — find the matching change in Gerrit).
2. In `zuul.d/job-templates.yaml`, template `neutron-tox-override-jobs` (and
   any other neutron-specific templates):
   - Add/remove `openstack-tox-py3XX` job overrides with timeouts and
     `irrelevant-files` anchors — copy structure from 985322
3. Match jobs already provided by `openstack-python3-jobs` in
   `zuul.d/project.yaml`; only override what neutron needs (timeouts, irrelevant
   files).
4. Apply equivalent changes in **neutron-lib** and stadium projects — search
   each repo for the previous cycle's "testing runtime" patch.

**Commit title:** `Update jobs based on testing runtime for <NEXT_RELEASE_ID>`

Skip this phase if governance did not change Python versions for the series.

---

## Phase 5 — Cycle highlights (final release)

**Reference:** [979359](https://review.opendev.org/c/openstack/releases/+/979359)

- **Repo:** `openstack/releases`
- **Branch:** `master`
- **When:** final GA of the series (not RC1)
- **Who:** PTL / release liaison

**How to implement:**

1. Open `deliverables/<codename>/neutron.yaml`.
2. Fill the `cycle-highlights:` list with bullet points — **user-visible**
   features shipped in the series (not internal refactors). Each item is a
   short prose line (see existing `deliverables/gazpacho/neutron.yaml`).
3. Coordinate with feature owners for accurate wording before RC/final.
4. Propose as a standalone releases patch near final release.

**Commit title:** `Neutron cycle highlights (<Codename> release)` or
`Add Neutron cycle highlights (<Codename> release)`

> **Note:** Writing good highlight text needs a dedicated **cycle highlights
> skill** (gathering features from specs, release notes, and driver teams).
> This skill covers only the YAML deliverable edit.

---

## Common Mistakes

- Starting Phase 3 before releases patches are merged
- Using patch commit instead of merge commit in releases YAML
- Adding current series to `NEUTRON_MILESTONES` before cycle ends
- Wrong SLURP patch (962240 vs 982005) for `.1` vs `.2` series
- Stable-branch tempest patches landed on `master` (must be `[<RELEASE_ID> only]`)
- `Depends-On` on `openstack/releases` patches

## References

- Official checklist: `doc/source/contributor/policies/release-checklist.rst`
- Stadium releases: `doc/source/contributor/stadium/guidelines.rst`
- Series status: `/opt/stack/releases/data/series_status.yaml`
- Individual releases: personal `openstack-new-release` skill
