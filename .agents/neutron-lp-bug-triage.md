# Neutron Launchpad Bug Triage

Summarize Neutron bugs filed on Launchpad in an inclusive date range, grouped
by importance, with assignee and active patch status. Use when triaging
Neutron bugs, preparing bug deputy reports, or producing a bug summary for a
given period.


## Workflow

1. **Determine the period** from the user request. Both start and end dates are
   inclusive (`YYYY-MM-DD`).

2. **Fetch bugs** by running the bundled script:

```bash
python3 .agents/scripts/list_launchpad_bugs.py \
  --start YYYY-MM-DD \
  --end YYYY-MM-DD \
  --json \
  --enrich
```

Run the command from the Neutron repository root.

Use `--project python-neutronclient` only when the user explicitly asks for
that project. Default is `neutron`.

3. **Verify patch status** for each bug:
   - Trust `active_patches` from `--enrich` first (Gerrit open changes, then
     Launchpad messages).
   - If a bug is `In Progress` or `Triaged` but `active_patches` is empty,
     read the bug page (`url` field) and confirm there is no active review on
     [review.opendev.org](https://review.opendev.org).

4. **Write the summary** using the presentation preferences and template below.


## Launchpad importance levels

Group bugs in this order. Include a section even when empty.

| Importance | Meaning (Launchpad default) |
|------------|----------------------------|
| **Critical** | Severe impact; blocks core functionality or causes data loss |
| **High** | Major impact; important work that should be addressed soon |
| **Medium** | Moderate impact; should be fixed but not urgent |
| **Low** | Minor issue or easy workaround |
| **Wishlist** | Feature request, not a defect |
| **Undecided** | Default for new bugs before triage |

Neutron may apply project-specific criteria, but always use these Launchpad
values for grouping.


## Active patch detection

A bug has an **active patch** when any of the following is true:

- Gerrit returns an open change (`status:open`) whose commit message references
  the bug ID.
- Launchpad has a "Fix proposed" or "Related fix proposed" message without a
  later "Change abandoned" or "Change merged" for the same review URL.

Report each active patch with its Gerrit URL and subject when available.


## Presentation preferences

The summary is **plain text**, ready to paste into an email. Do not use
Markdown formatting in the output (no `#` headers, no `**bold**`, no
`[links](url)`, no tables, no separator lines).

Rules:

- Write flowing prose, not boxed or column-aligned layouts.
- Group bugs by importance. Use a simple label followed by a blank line and
  the bug entries (for example: `Critical:`).
- Prefix each bug entry with `* ` (asterisk and space).
- Each bug is a single paragraph with fields separated by periods, in this
  order: Bug ID, title, Created, Status, Assignee, Link, Active patch.
- Use full URLs for the bug link and any Gerrit review.
- When there is an active patch, write `Active patch: <subject>. <gerrit-url>`.
  Do not write `Active patch: Yes`.
- When there is no active patch, write `Active patch: No.`
- Empty importance sections: write `None.` on the line after the section label.
- End with a short `Triage notes:` paragraph when relevant.
- Within each importance section, list bugs oldest-first (the script already
  returns them in creation order).


## Summary template

```
Neutron Launchpad bug summary for YYYY-MM-DD to YYYY-MM-DD (inclusive). Total bugs: N.

Overview: Critical N, High N, Medium N, Low N, Wishlist N, Undecided N. With active patch: N. Unassigned: N.

Critical:

* Bug NNNNNN - <title>. Created YYYY-MM-DD. Status <status>. Assignee <name or Unassigned>. Link https://bugs.launchpad.net/neutron/+bug/NNNNNN. Active patch: No.

High:

* Bug NNNNNN - <title>. Created YYYY-MM-DD. Status <status>. Assignee <name or Unassigned>. Link https://bugs.launchpad.net/neutron/+bug/NNNNNN. Active patch: <subject>. https://review.opendev.org/c/openstack/neutron/+/NNNNNN

Medium:

...

Low: None.

Wishlist: None.

Undecided: None.

Triage notes: <brief observations>
```


## Script reference

`.agents/scripts/list_launchpad_bugs.py` queries the Launchpad REST API and
optionally enriches each bug with:

- `assignee` — resolved from Launchpad; `Unassigned` when empty
- `active_patches` — open Gerrit changes or unresolved Launchpad patch messages

Example:

```bash
python3 .agents/scripts/list_launchpad_bugs.py --start 2026-05-26 --end 2026-05-27 --json --enrich
```

JSON fields per bug: `id`, `created`, `status`, `importance`, `title`, `url`,
`assignee`, `active_patches`.


## Notes

- Neutron bugs live at https://bugs.launchpad.net/neutron
- `--enrich` may be slow (~30–60 s per bug) because Gerrit searches are slow;
  keep date ranges focused.
- Do not use JIRA for Neutron community bugs; they are tracked in Launchpad.
