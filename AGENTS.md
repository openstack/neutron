# AGENTS.md — agent routing index

Agents: explore the repo directly; this file is a routing index, not a contributor guide.


## Workflow

**Session memory:** Write plans, notes, and ephemeral files to `.tmp/`
(gitignored) rather than the system temporary directory.

**For non-trivial planning**, inspect deps and tooling:
`pyproject.toml` · `tox.ini` · `.pre-commit-config.yaml` ·
`requirements.txt` · `test-requirements.txt`

**Tests**: Use `tox` or `stestr`; never use `pytest`.
  Invoke them directly, for example `tox -e pep8`.
  Assume project tools are installed and available on `$PATH`.

**Routing:**
- Repo layout: [doc/source/contributor/repo-overview.rst](doc/source/contributor/repo-overview.rst)
- Style, hacking, checks: [HACKING.rst](HACKING.rst)
- Test conventions, fixtures: [HACKING.rst](HACKING.rst) / [TESTING.rst](TESTING.rst)
- REST API: [Networking Services APIs](https://opendev.org/openstack/neutron-lib/src/branch/master/api-ref/source/index.rst))


## Project Links

- **Repository**: https://opendev.org/openstack/neutron (GitHub is a mirror only)
- **Bug tracking**: https://bugs.launchpad.net/neutron
- **Code review**: Gerrit at https://review.opendev.org (not GitHub PRs)
- **Docs**: https://docs.openstack.org/neutron/latest/
- **Contributor guide**: `doc/source/contributor/` in the Neutron repository
- **Specs**: `openstack/neutron-specs` — `specs/<release>/approved/`,
  `specs/<release>/implemented/`, `specs/backlog/`, `specs/abandoned/`


## Dependencies

The Neutron project depends on different libraries. These are the most important
and controlled (partially) by the Neutron team:
- [ovsdbapp](https://opendev.org/openstack/ovsdbapp)
- [python-ovs](https://github.com/openvswitch/ovs/tree/main/python)
- [neutron-lib](https://opendev.org/openstack/neutron-lib)
- [sqlalchemy](https://github.com/sqlalchemy/sqlalchemy)
- [os-ken](https://opendev.org/openstack/os-ken)
- [oslo.privsep](https://opendev.org/openstack/oslo.privsep)
- [oslo.db](https://opendev.org/openstack/oslo.db)
- [oslo.service](https://opendev.org/openstack/oslo.service)
- [oslo.config](https://opendev.org/openstack/oslo.config)
- [pyroute2](https://github.com/svinota/pyroute2)


## Guardrails

- **Tools:** Do not install missing tools with a package manager or `pip`
- **Concurrency**: Do not introduce asyncio or new eventlet usage. Review the
  threading and concurrency docs when changing concurrent code.
- **Review**: Neutron uses Gerrit, not GitHub PRs. Series are always
  unsquashed; each commit must be independently testable and correct.
- **Git**: Read-only operations (`git log`, `git diff`, `git status`) are fine.
  Do not run mutating operations (`add`, `commit`, `reset`, `checkout`, `push`,
  `stash`, `merge`, `rebase`, etc.) unless explicitly instructed to do so.
