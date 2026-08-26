---
description: >-
  Git commit message formatting rules for the Neutron repository: mandatory
  trailers (Assisted-By, Signed-off-by, Change-Id), trailer ordering and
  preservation, heredoc quoting, and style conventions. Use when creating,
  amending, or rewording git commits.
alwaysApply: false
---

# Git Commit Message Formatting

Rules for formatting commit messages in the Neutron repository. The author
identity comes from the user's personal configuration (e.g. `git config
user.name` / `git config user.email` or an external git-identity rule).


## Commit message trailers

Every commit message must end with a trailer block. The **mandatory** trailers
are (in this relative order, always at the bottom):

```
Assisted-By: <model name>
Signed-off-by: <author name> <author email>
Change-Id: <generated or preserved Change-Id>
```

### Mandatory trailer rules

- Add a `Signed-off-by` using the author's configured git identity only when
  no other `Signed-off-by` already exists in the commit.
- Update the model name if the underlying model changes. Use the model name
  without the company name (e.g. `Claude Opus 4.6`, not
  `Anthropic Claude Opus 4.6`).
- `Change-Id` is always the very last line of the commit message.

### Preserving existing trailers

When amending or rewording a commit that already contains trailers, preserve
them:

- **Change-Id** — always keep the existing value; never regenerate it.
- **Related-Bug:** / **Closes-Bug:** — preserve any `Related-Bug: #...`
  or `Closes-Bug: #...` references.
- **Co-Authored-By** — preserve any existing `Co-Authored-By:` lines.
  (Do NOT add new ones.)
- **Signed-off-by** — if the commit already has a `Signed-off-by:` from
  someone other than the current author, preserve it and do **not** add the
  author's own `Signed-off-by`. Only add the author's `Signed-off-by` when
  no other `Signed-off-by` is present.

Place preserved trailers **above** `Assisted-By`. Lines marked `(optional)`
appear only when the original commit had them:

```
Related-Bug: #<number>                          (optional)
Closes-Bug: #<number>                           (optional)
Assisted-By: <model name>
Signed-off-by: Other Person <other@example.com> (if present, replaces author SOB)
Co-Authored-By: Name <email>                    (optional)
Change-Id: I<preserved>
```

When no external `Signed-off-by` exists (the common case):

```
Assisted-By: <model name>
Signed-off-by: <author name> <author email>
Change-Id: I<generated or preserved>
```


## Commit message style

- Wrap method, function, and variable names in double backticks
  (``` `` ```), e.g. ``_delete_port()``, ``ls_get()``.
- The title may include a lowercase prefix followed by `:` to indicate the
  subsystem or area, e.g. `ovn:`, `dhcp:`, `l3:`, `ovs:`, `ml2:`, `ai:`. Only
  add a prefix when the change is scoped to a specific subsystem.


## Commit via shell

- Only create commits when the user explicitly asks.
- Use `--author` **and** `GIT_COMMITTER_NAME` / `GIT_COMMITTER_EMAIL` from
  the author's configured git identity. Both author and committer must match
  to avoid Gerrit rejections.
- Pass the message with a **quoted** heredoc so backticks are not stripped
  by bash command substitution:

```bash
GIT_COMMITTER_NAME="Author Name" GIT_COMMITTER_EMAIL="author@example.com" \
  git commit --author="Author Name <author@example.com>" -m "$(cat <<'EOF'
doc: Document runtime ``uwsgi`` Python module in WSGI guide

Explain that the ``uwsgi`` module is injected at runtime by the uWSGI
server and is used by ``neutron.common.wsgi_utils`` for options such
as ``start-time`` and ``uwsgi.worker_id()``.

Assisted-By: Composer 2.5
Signed-off-by: Author Name <author@example.com>
Change-Id: I<generated-or-preserved>
EOF
)"
```

(`--author`, committer env vars, and `Signed-off-by` must all use the same
identity.)

- Use `<<'EOF'` (quoted delimiter), not `<<EOF`. Unquoted heredocs treat
  `` `...` `` as command substitution and silently remove backticks from the
  message.
- Generate `Change-Id` for new commits; preserve the original `Change-Id`
  when amending.
