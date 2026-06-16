#!/usr/bin/env python3
"""
dep_version_diff.py: Show dependency version changes that affect a neutron CI
job between two points in time or neutron commits.

The tool understands two constraint-update pipelines:
  - OpenStack projects: manual per-release patch to requirements repo
  - External packages: generate-constraints bot sweeps PyPI periodically

Usage examples:
  # Changes over a date range (requirements repo timeline):
  ./tools/dep_version_diff.py --start 2026-05-25 --end 2026-06-06

  # Between two neutron commits (derives dates, finds requirements state):
  ./tools/dep_version_diff.py --neutron-start abc1234 --neutron-end def5678

  # Filter to packages relevant to a specific job:
  ./tools/dep_version_diff.py --start 2026-05-25 --job neutron-functional
  ./tools/dep_version_diff.py --start 2026-05-25 \\
      --job neutron-functional-with-neutron-lib-master

  # Show all constraint changes (not just neutron deps):
  ./tools/dep_version_diff.py --start 2026-05-25 --all

  # Use a shared workspace for companion repos (clones missing repos on first
  # run, reuses existing clones on subsequent runs):
  ./tools/dep_version_diff.py --start 2026-06-05 --branch-commits \\
      --path /tmp/neutron-dep-workspace/
"""

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_NEUTRON_REPO = Path(__file__).resolve().parents[1]
_GIT_BIN = shutil.which('git') or 'git'

REPO_URLS = {
    'requirements': 'https://opendev.org/openstack/requirements',
    'ovn': 'https://github.com/ovn-org/ovn',
    'ovs': 'https://github.com/openvswitch/ovs',
}


def find_repo(name, neutron_repo):
    """Search common locations for a companion repo.

    Search order:
      1. Sibling of the neutron repo — covers both ~/src/ and /opt/stack/
         with a single rule since devstack clones everything into the same dir.
      2. ~/src/<name>  — explicit fallback when neutron lives elsewhere.
      3. /opt/stack/<name> — explicit devstack fallback.
    """
    candidates = [
        neutron_repo.parent / name,
        Path.home() / 'src' / name,
        Path('/opt/stack') / name,
    ]
    for p in candidates:
        if (p / '.git').exists():
            return p
    return None


def ensure_repo(name, explicit_path, neutron_repo, clone_to=None):
    """Return a usable repo Path, discovering or cloning if needed.

    Args:
        name:          short name used for discovery and cloning (e.g. 'ovn')
        explicit_path: value from the --xxx-repo CLI flag (may be None)
        neutron_repo:  used as the anchor for sibling discovery
        clone_to:      if set (--path), use/clone repos here; skips discovery

    When --path is given it acts as a self-contained workspace:
      - if the repo already exists there, reuse it
      - otherwise clone it from upstream
    Auto-discovery (sibling / ~/src / /opt/stack) is only used when
    --path is not given.
    """
    # Explicit path always wins if it points at a real git repo
    if explicit_path and (explicit_path / '.git').exists():
        return explicit_path

    # --path overrides discovery: use the workspace exclusively
    if clone_to and name in REPO_URLS:
        target = Path(clone_to) / name
        if not (target / '.git').exists():
            print(f'  cloning {name} from {REPO_URLS[name]} → {target}',
                  file=sys.stderr)
            subprocess.run(  # noqa: S603
                [_GIT_BIN, 'clone', REPO_URLS[name], str(target)],
                check=True)
        return target

    # Auto-discover in common locations
    found = find_repo(name, neutron_repo)
    if found:
        return found

    return explicit_path  # may be None — callers handle that


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def _git(repo, *args):
    r = subprocess.run(  # noqa: S603
        [_GIT_BIN, '-C', str(repo)] + list(args),
        capture_output=True, text=True, check=False)
    return r.stdout.strip() if r.returncode == 0 else None


def resolve_ref(repo, ref_or_date):
    """Resolve a date (YYYY-MM-DD) or git ref to a full commit hash."""
    if re.match(r'^\d{4}-\d{2}-\d{2}', ref_or_date):
        # Date: find last commit on HEAD on or before midnight of that day.
        for branch in ('HEAD', 'origin/master', 'origin/main'):
            commit = _git(repo, 'rev-list', '-1',
                          f'--before={ref_or_date}T23:59:59', branch)
            if commit:
                return commit
        return None
    return _git(repo, 'rev-parse', '--verify', ref_or_date)


def commit_date(repo, ref):
    return _git(repo, 'log', '-1', '--format=%cd', '--date=short', ref)


def file_at(repo, ref, path):
    return _git(repo, 'show', f'{ref}:{path}')


def req_ref_for_date(req_repo, date_str):
    """Find the requirements repo commit on or before the given date."""
    for branch in ('HEAD', 'origin/master', 'origin/main'):
        commit = _git(req_repo, 'rev-list', '-1',
                      f'--before={date_str}T23:59:59', branch)
        if commit:
            return commit
    return None


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _norm(name):
    """PEP 503 normalization: collapse [-_.] to '-' and lowercase."""
    return re.sub(r'[-_.]+', '-', name).lower()


def parse_upper_constraints(content):
    """Return {normalized_name: version} from upper-constraints.txt content."""
    result = {}
    for line in (content or '').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        m = re.match(r'^([A-Za-z0-9_.\-]+)===(.+)$', line)
        if m:
            result[_norm(m.group(1))] = m.group(2)
    return result


def parse_req_names(content):
    """Return set of normalized package names from a requirements file."""
    names = set()
    for line in (content or '').splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('-'):
            continue
        m = re.match(r'^([A-Za-z0-9_.\-]+)', line)
        if m:
            names.add(_norm(m.group(1)))
    return names


def neutron_dep_names(neutron_repo, ref):
    """All direct dep names pulled in for the functional job at ref."""
    dep_files = [
        'requirements.txt',
        'test-requirements.txt',
        'neutron/tests/functional/requirements.txt',
    ]
    names = set()
    for f in dep_files:
        names |= parse_req_names(file_at(neutron_repo, ref, f))
    return names


def from_source_packages(neutron_repo, ref, job_name):
    """
    Return packages installed from source (not pinned by constraints) for
    the given job.  Walks the zuul.d/base.yaml job hierarchy collecting
    required-projects, then maps repo names to package names.
    """
    content = file_at(neutron_repo, ref, 'zuul.d/base.yaml')
    if not content:
        return set()

    # Simple regex-based YAML extraction to avoid requiring PyYAML.
    # Pull every "name: <jobname>" / "parent: <jobname>" / "required-projects:"
    # block without a full YAML parse.
    jobs = {}  # name -> {parent, required_projects}
    current_job = None
    in_req_projects = False

    for line in content.splitlines():
        # Detect start of a job block
        m = re.match(r'^\s{4}name:\s+(\S+)', line)
        if m:
            current_job = m.group(1)
            jobs.setdefault(current_job, {'parent': None, 'projects': []})
            in_req_projects = False
            continue

        if current_job is None:
            continue

        m = re.match(r'^\s{4}parent:\s+(\S+)', line)
        if m:
            jobs[current_job]['parent'] = m.group(1)
            continue

        if re.match(r'^\s{4}required-projects:', line):
            in_req_projects = True
            continue

        # Once we hit another 4-space key, we're out of required-projects
        if in_req_projects and re.match(r'^\s{4}\w', line):
            in_req_projects = False

        if in_req_projects:
            # Match "- openstack/foo" or "- name: openstack/foo"
            m = (re.match(r'^\s+[-]\s+name:\s+(\S+)', line) or
                 re.match(r'^\s+[-]\s+(\S+)', line))
            if m:
                jobs[current_job]['projects'].append(m.group(1))

    # Walk the hierarchy to collect all required-projects for the target job
    def collect(name, visited=None):
        if visited is None:
            visited = set()
        if name in visited or name not in jobs:
            return []
        visited.add(name)
        projs = list(jobs[name]['projects'])
        parent = jobs[name]['parent']
        if parent:
            projs += collect(parent, visited)
        return projs

    source_pkgs = set()
    for repo_path in collect(job_name):
        # e.g. "openstack/neutron-lib" -> "neutron-lib"
        #       "github.com/svinota/pyroute2" -> "pyroute2"
        pkg = repo_path.rstrip('/').split('/')[-1]
        source_pkgs.add(_norm(pkg))
    return source_pkgs


# ---------------------------------------------------------------------------
# OVS/OVN branch tracking
# ---------------------------------------------------------------------------

def classify_ref(value):
    """Return a stability label for an OVS/OVN branch value."""
    if re.match(r'^[0-9a-f]{7,40}$', value):
        return 'commit (fixed)'
    if re.match(r'^v?\d+\.\d+\.\d+', value):
        return 'tag (fixed)'
    return 'branch (moving)'


def _parse_zuul_job_branch_vars(content):
    """
    Parse zuul.d yaml content and return
    {job_name: {'parent': str|None, 'OVS_BRANCH': str, 'OVN_BRANCH': str}}.
    Uses a line-by-line state machine to avoid requiring PyYAML.
    """
    jobs = {}
    current = None
    in_vars = False

    for line in content.splitlines():
        # Job name — always at exactly 4 spaces
        m = re.match(r'^    name:\s+(\S+)', line)
        if m:
            current = m.group(1)
            jobs.setdefault(current, {'parent': None})
            in_vars = False
            continue

        if current is None:
            continue

        m = re.match(r'^    parent:\s+(\S+)', line)
        if m:
            jobs[current]['parent'] = m.group(1)
            continue

        if re.match(r'^    vars:\s*$', line):
            in_vars = True
            continue

        # Another 4-space key ends the vars block
        if in_vars and re.match(r'^    \w', line):
            in_vars = False

        if in_vars:
            m = re.match(r'^\s+(OVS_BRANCH|OVN_BRANCH):\s+"?([^"#\n]+?)"?\s*$',
                         line)
            if m:
                jobs[current][m.group(1)] = m.group(2).strip()

    return jobs


def get_ovs_ovn_branches(neutron_repo, ref, job_name=None):
    """
    Return {'OVS_BRANCH': value, 'OVN_BRANCH': value} for the job at ref.

    Priority:
      1. Job vars in zuul.d files (child overrides parent)
      2. Defaults in tools/configure_for_func_testing.sh
    """
    branches = {}

    if job_name:
        # Collect all jobs from every zuul.d file
        tree = _git(neutron_repo, 'ls-tree', '--name-only', ref, 'zuul.d/')
        all_jobs = {}
        for fname in (tree or '').splitlines():
            if fname.endswith(('.yaml', '.yml')):
                content = file_at(neutron_repo, ref, fname) or ''
                all_jobs.update(_parse_zuul_job_branch_vars(content))

        # Walk the parent chain; child values win (already set → skip)
        visited = set()
        queue = [job_name]
        while queue:
            name = queue.pop(0)
            if name in visited or name not in all_jobs:
                continue
            visited.add(name)
            job = all_jobs[name]
            for key in ('OVS_BRANCH', 'OVN_BRANCH'):
                if key not in branches and key in job:
                    branches[key] = job[key]
            if job.get('parent'):
                queue.append(job['parent'])

    # Fall back to configure script defaults for any missing values
    script = file_at(neutron_repo, ref,
                     'tools/configure_for_func_testing.sh') or ''
    for line in script.splitlines():
        m = re.match(r'(OVS_BRANCH|OVN_BRANCH)=\$\{\1:-([^}]+)\}', line)
        if m and m.group(1) not in branches:
            branches[m.group(1)] = m.group(2)

    return branches


def _merge_commit_info(repo, sha):
    """
    Return (date, subject, sha8) for a commit, using the merge commit's date
    and SHA (both on the first-parent chain and findable with plain git log)
    but the patch commit's subject (cleaner than "Merge \"...\"").
    Falls back to the commit itself if it has no second parent.
    """
    date = _git(repo, 'log', '-1', '--format=%cd', '--date=short', sha)
    # Try to get the subject from the second parent (the patch commit)
    patch_subject = _git(repo, 'log', '-1', '--format=%s', f'{sha}^2')
    subject = patch_subject if patch_subject else \
        _git(repo, 'log', '-1', '--format=%s', sha)
    return date, subject, sha[:8]


def get_branch_commits(repo, branch, since_date, until_date):
    """
    Return list of (sha8, subject) for commits on a branch between two dates.
    Tries origin/<branch> first, then <branch> as a local ref.
    Returns None if the repo doesn't exist or the branch can't be found.
    Returns [] if the branch exists but has no commits in range.
    """
    if not Path(repo).exists():
        return None
    for ref in (f'origin/{branch}', branch):
        out = _git(repo, 'log', '--format=%h\t%s',
                   f'--since={since_date}T00:00:00',
                   f'--until={until_date}T23:59:59',
                   ref, '--')
        if out is not None:
            result = []
            for line in out.splitlines():
                if '\t' in line:
                    sha, subj = line.split('\t', 1)
                    result.append((sha, subj))
            return result
    return None


def build_ovs_ovn_change_map(neutron_repo, start_ref, end_ref, job_name):
    """
    Return {var_name: (date, subject, sha8, repo_name)} for OVS_BRANCH /
    OVN_BRANCH changes between start_ref and end_ref.
    """
    watch = ['tools/configure_for_func_testing.sh']
    # Also watch the zuul.d files that are likely to carry job-level vars
    tree = _git(neutron_repo, 'ls-tree', '--name-only', end_ref, 'zuul.d/')
    for fname in (tree or '').splitlines():
        if fname.endswith(('.yaml', '.yml')):
            watch.append(fname)

    shas = _git(neutron_repo, 'log', '--first-parent', '--format=%H',
                f'{start_ref}..{end_ref}', '--', *watch)
    if not shas:
        return {}

    repo_name = Path(neutron_repo).name
    change_map = {}

    for sha in shas.splitlines():
        parent = _git(neutron_repo, 'rev-parse', f'{sha}^')
        if not parent:
            continue
        before = get_ovs_ovn_branches(neutron_repo, parent, job_name)
        after = get_ovs_ovn_branches(neutron_repo, sha, job_name)
        for key in ('OVS_BRANCH', 'OVN_BRANCH'):
            if before.get(key) != after.get(key) and key not in change_map:
                date, subject, sha8 = _merge_commit_info(neutron_repo, sha)
                change_map[key] = (date, subject, sha8, repo_name)

    return change_map


# ---------------------------------------------------------------------------
# Change attribution
# ---------------------------------------------------------------------------

def build_neutron_dep_change_map(neutron_repo, start_ref, end_ref):
    """
    Walk neutron commits in start_ref..end_ref that touched dep files and
    return {pkg: (date, subject, sha8, 'neutron')} for each package whose
    presence in the dep set changed.  Walking newest-first means the first
    hit is authoritative.
    """
    dep_files = [
        'requirements.txt',
        'test-requirements.txt',
        'neutron/tests/functional/requirements.txt',
    ]
    shas = _git(neutron_repo, 'log', '--first-parent', '--format=%H',
                f'{start_ref}..{end_ref}', '--', *dep_files)
    if not shas:
        return {}

    repo_name = Path(neutron_repo).name
    change_map = {}

    for sha in shas.splitlines():
        parent = _git(neutron_repo, 'rev-parse', f'{sha}^')
        if not parent:
            continue
        before = set()
        after = set()
        for f in dep_files:
            before |= parse_req_names(file_at(neutron_repo, parent, f))
            after |= parse_req_names(file_at(neutron_repo, sha, f))
        for pkg in (before ^ after):
            if pkg not in change_map:
                date, subject, sha8 = _merge_commit_info(neutron_repo, sha)
                change_map[pkg] = (date, subject, sha8, repo_name)

    return change_map


def build_change_map(req_repo, start_ref, end_ref):
    """
    Walk commits in start_ref..end_ref that touched upper-constraints.txt
    and return {pkg: (date, subject, sha8, repo_name)} recording the most
    recent commit that changed each package's pinned version.  Walking
    newest-first means the first hit for a package is the authoritative one.
    """
    shas = _git(req_repo, 'log', '--no-merges', '--format=%H',
                f'{start_ref}..{end_ref}', '--', 'upper-constraints.txt')
    if not shas:
        return {}

    repo_name = Path(req_repo).name

    change_map = {}
    for sha in shas.splitlines():
        date = _git(req_repo, 'log', '-1', '--format=%cd', '--date=short', sha)
        subject = _git(req_repo, 'log', '-1', '--format=%s', sha)
        parent = _git(req_repo, 'rev-parse', f'{sha}^')
        if not parent:
            continue
        before = parse_upper_constraints(
            file_at(req_repo, parent, 'upper-constraints.txt'))
        after = parse_upper_constraints(
            file_at(req_repo, sha, 'upper-constraints.txt'))
        for pkg in set(before) | set(after):
            if before.get(pkg) != after.get(pkg) and pkg not in change_map:
                change_map[pkg] = (date, subject, sha[:8], repo_name)

    return change_map


def classify_source(subject):
    """Return a short source tag based on the commit subject."""
    if 'generate-constraints' in subject:
        return 'bot'
    if re.match(r'update constraint for .+ to new release', subject,
                re.IGNORECASE):
        return 'release'
    return 'manual'


# ---------------------------------------------------------------------------
# Core diff logic
# ---------------------------------------------------------------------------

def diff_constraints(start, end, relevant=None, exclude=None):
    """
    Diff two {name: version} dicts.

    Args:
        start, end: constraint dicts
        relevant: if not None, only consider these package names
        exclude: package names to skip (from-source packages)

    Returns:
        (changed, added, removed) lists of (name, old_ver, new_ver) tuples
        where old_ver/new_ver is None for added/removed entries.
    """
    exclude = exclude or set()
    all_pkgs = set(start) | set(end)
    if relevant is not None:
        all_pkgs &= relevant

    changed, added, removed = [], [], []
    for pkg in sorted(all_pkgs - exclude):
        old = start.get(pkg)
        new = end.get(pkg)
        if old == new:
            continue
        if old and new:
            changed.append((pkg, old, new))
        elif new:
            added.append((pkg, None, new))
        else:
            removed.append((pkg, old, None))

    return changed, added, removed


def fmt_attribution(pkg, change_map):
    """Format the date/source/sha attribution for a changed package."""
    if pkg not in change_map:
        return ''
    date, subject, sha8, repo_name = change_map[pkg]
    tag = classify_source(subject)
    subj = subject if len(subject) <= 52 else subject[:49] + '...'
    return f'  {date}  [{tag}] {subj}  ({repo_name}@{sha8})'


def print_rows(rows, label, change_map):
    """Print a section of (pkg, old_ver, new_ver) rows with attribution."""
    print(f'{label}:')
    name_w = max(len(pkg) for pkg, _, _ in rows)
    ver_w = max(len(f'{o} -> {n}') if o and n else
                len(f'(new) {n}') if n else len(f'{o} (dropped)')
                for _, o, n in rows)
    for pkg, old, new in rows:
        ver_str = f'{old} -> {new}' if old and new else \
                  f'(new) {new}' if new else f'{old} (dropped)'
        attr = fmt_attribution(pkg, change_map)
        print(f'  {pkg:<{name_w}}  {ver_str:<{ver_w}}{attr}')


def _print_branch_commits(key, branch, commits, indent_w=10):
    """Print branch commit list under an OVS/OVN branch entry."""
    pad = ' ' * (indent_w + 4)
    if commits is None:
        print(f'{pad}(repo not found for {branch} commits)')
    elif not commits:
        print(f'{pad}(no commits on {branch} in this date range)')
    else:
        print(f'{pad}{len(commits)} commit(s) on {branch}:')
        for sha, subj in commits:
            subj_t = subj if len(subj) <= 72 else subj[:69] + '...'
            print(f'{pad}  {sha}  {subj_t}')


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _resolve_refs(args, neutron_repo, req_repo):
    """Resolve start/end refs for both the requirements and neutron repos.

    Returns:
        (req_start, req_end, neutron_ref, neutron_start_ref,
         start_date, end_date, start_label, end_label)
    """
    if args.neutron_start:
        nstart = resolve_ref(neutron_repo, args.neutron_start)
        if not nstart:
            sys.exit(
                f'error: cannot resolve neutron start: {args.neutron_start}')
        start_date = commit_date(neutron_repo, nstart)
        req_start = req_ref_for_date(req_repo, start_date)
        neutron_start_ref = nstart
        start_label = (
            f'{args.neutron_start[:8]} (neutron) -> {start_date}')
    else:
        req_start = resolve_ref(req_repo, args.start)
        start_date = commit_date(req_repo, req_start)
        neutron_start_ref = resolve_ref(neutron_repo, start_date)
        start_label = args.start

    if args.neutron_end:
        nend = resolve_ref(neutron_repo, args.neutron_end)
        if not nend:
            sys.exit(
                f'error: cannot resolve neutron end: {args.neutron_end}')
        end_date = commit_date(neutron_repo, nend)
        req_end = req_ref_for_date(req_repo, end_date)
        end_label = f'{args.neutron_end[:8]} (neutron) -> {end_date}'
        neutron_ref = nend
    else:
        req_end = resolve_ref(req_repo, args.end)
        end_label = args.end
        neutron_ref = resolve_ref(neutron_repo, args.neutron_ref)
        end_date = commit_date(req_repo, req_end)

    for label, val in [('requirements start', req_start),
                       ('requirements end', req_end),
                       ('neutron ref', neutron_ref)]:
        if not val:
            sys.exit(f'error: cannot resolve {label}')

    return (req_start, req_end, neutron_ref, neutron_start_ref,
            start_date, end_date, start_label, end_label)


def main():
    p = argparse.ArgumentParser(
        description='Diff pinned dependency versions that affect a neutron '
                    'job.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split('Usage examples:')[1])

    start_group = p.add_mutually_exclusive_group(required=True)
    start_group.add_argument(
        '--start', metavar='DATE_OR_REF',
        help='Start date (YYYY-MM-DD) or requirements repo commit/ref')
    start_group.add_argument(
        '--neutron-start', metavar='COMMIT',
        help='Start neutron commit; date is derived to find requirements '
             'state')

    p.add_argument(
        '--end', metavar='DATE_OR_REF', default='HEAD',
        help='End date or requirements repo ref (default: HEAD)')
    p.add_argument(
        '--neutron-end', metavar='COMMIT',
        help='End neutron commit; date is derived to find requirements state')

    p.add_argument(
        '--neutron-ref', metavar='REF', default='HEAD',
        help='Neutron ref to read dep files from (default: HEAD). '
             'Ignored when --neutron-end is set.')
    p.add_argument(
        '--job', metavar='JOB_NAME',
        help='Zuul job name; packages installed from source for this job '
             'are excluded from the diff (e.g. neutron-functional, '
             'neutron-functional-with-neutron-lib-master)')
    p.add_argument(
        '--all', dest='show_all', action='store_true',
        help='Show all constraint changes, not just neutron direct deps')

    p.add_argument(
        '--neutron-repo', type=Path, default=DEFAULT_NEUTRON_REPO,
        help=f'Path to neutron repo (default: {DEFAULT_NEUTRON_REPO})')
    p.add_argument(
        '--requirements-repo', type=Path, default=None,
        help='Path to requirements repo (auto-discovered if omitted)')
    p.add_argument(
        '--ovn-repo', type=Path, default=None,
        help='Path to OVN repo (auto-discovered if omitted)')
    p.add_argument(
        '--ovs-repo', type=Path, default=None,
        help='Path to OVS repo (auto-discovered if omitted)')
    p.add_argument(
        '--path', metavar='DIR',
        help='Workspace directory for companion repos (requirements, ovn, '
             'ovs). Repos already present are reused; missing ones are '
             'cloned from upstream. Overrides auto-discovery.')
    p.add_argument(
        '--branch-commits', action='store_true',
        help='For moving OVS/OVN branches, show commits within the date range')

    args = p.parse_args()
    neutron_repo = args.neutron_repo

    req_repo = ensure_repo('requirements', args.requirements_repo,
                           neutron_repo, args.path)
    ovn_repo = ensure_repo('ovn', args.ovn_repo, neutron_repo, args.path)
    ovs_repo = ensure_repo('ovs', args.ovs_repo, neutron_repo, args.path)

    if not req_repo or not (req_repo / '.git').exists():
        sys.exit(
            'error: requirements repo not found — use --requirements-repo '
            'or --path to provide it')

    (req_start, req_end, neutron_ref, neutron_start_ref,
     start_date, end_date, start_label, end_label) = _resolve_refs(
        args, neutron_repo, req_repo)

    # --- Load constraints ---
    start_uc = parse_upper_constraints(
        file_at(req_repo, req_start, 'upper-constraints.txt'))
    end_uc = parse_upper_constraints(
        file_at(req_repo, req_end, 'upper-constraints.txt'))

    if not start_uc:
        sys.exit('error: could not read upper-constraints.txt at start ref')
    if not end_uc:
        sys.exit('error: could not read upper-constraints.txt at end ref')

    # --- Build filter sets ---
    start_deps = neutron_dep_names(neutron_repo, neutron_start_ref) \
        if neutron_start_ref else set()
    end_deps = neutron_dep_names(neutron_repo, neutron_ref)

    relevant = None if args.show_all else end_deps
    if relevant is not None and not relevant:
        print('warning: could not read neutron dep files; showing all changes',
              file=sys.stderr)
        relevant = None

    source_pkgs = set()
    if args.job:
        source_pkgs = from_source_packages(neutron_repo, neutron_ref, args.job)

    # --- Diff constraints ---
    changed, added, removed = diff_constraints(start_uc, end_uc,
                                               relevant=relevant,
                                               exclude=source_pkgs)

    # --- Neutron dep set changes (independent of constraint changes) ---
    # Packages newly added to or removed from neutron's requirements files.
    newly_required = []
    no_longer_required = []
    if not args.show_all and start_deps:
        for pkg in sorted((end_deps - start_deps) - source_pkgs):
            ver = end_uc.get(pkg, '(unconstrained)')
            newly_required.append((pkg, None, ver))
        for pkg in sorted((start_deps - end_deps) - source_pkgs):
            ver = start_uc.get(pkg, '(unconstrained)')
            no_longer_required.append((pkg, ver, None))

    # --- OVS/OVN binary branch changes ---
    ovs_ovn_changes = []
    ovs_ovn_change_map = {}
    end_branches = {}
    if neutron_start_ref or args.branch_commits:
        end_branches = get_ovs_ovn_branches(
            neutron_repo, neutron_ref, args.job)
    if neutron_start_ref:
        start_branches = get_ovs_ovn_branches(neutron_repo, neutron_start_ref,
                                              args.job)
        for key in ('OVS_BRANCH', 'OVN_BRANCH'):
            old = start_branches.get(key, '?')
            new = end_branches.get(key, '?')
            if old != new:
                ovs_ovn_changes.append((key, old, new))
        if ovs_ovn_changes:
            ovs_ovn_change_map = build_ovs_ovn_change_map(
                neutron_repo, neutron_start_ref, neutron_ref,
                args.job or 'neutron-functional')

    # --- Attribution: find which commit introduced each change ---
    change_map = build_change_map(req_repo, req_start, req_end)
    if neutron_start_ref:
        change_map.update(
            build_neutron_dep_change_map(neutron_repo, neutron_start_ref,
                                         neutron_ref))
        change_map.update(ovs_ovn_change_map)

    # --- Output ---
    req_start_date = commit_date(req_repo, req_start)
    req_end_date = commit_date(req_repo, req_end)

    scope = 'all constraints' if args.show_all else 'neutron direct deps'
    print(f'Dependency changes ({scope})')
    print(f'  start : {start_label}')
    print(f'    -> requirements {req_start[:8]} ({req_start_date})')
    print(f'  end   : {end_label}')
    print(f'    -> requirements {req_end[:8]} ({req_end_date})')
    print(f'  neutron deps read from: {neutron_ref[:8]}')
    if args.job:
        print(f'  job: {args.job}')
        if source_pkgs:
            print(
                f'  from-source (excluded): {", ".join(sorted(source_pkgs))}')
    print()

    has_branch_content = args.branch_commits and any(
        classify_ref(end_branches.get(k, '')) == 'branch (moving)'
        for k in ('OVS_BRANCH', 'OVN_BRANCH')
    )
    if not any([changed, added, removed, newly_required, no_longer_required,
                ovs_ovn_changes]) and not has_branch_content:
        print('No relevant dependency changes in this range.')
        return

    if changed:
        print_rows(changed, 'Changed', change_map)

    if added:
        print()
        print_rows(added, 'Added to constraints', change_map)

    if removed:
        print()
        print_rows(removed, 'Removed from constraints', change_map)

    if newly_required:
        print()
        print_rows(newly_required, 'Newly required by neutron', change_map)

    if no_longer_required:
        print()
        print_rows(no_longer_required,
                   'No longer required by neutron', change_map)

    if ovs_ovn_changes or (args.branch_commits and not args.show_all):
        # Also show unchanged moving branches when --branch-commits requested
        all_branch_keys = set(k for k, _, _ in ovs_ovn_changes)
        if args.branch_commits:
            for key in ('OVS_BRANCH', 'OVN_BRANCH'):
                val = end_branches.get(key, '')
                if classify_ref(val) == 'branch (moving)':
                    all_branch_keys.add(key)

        if ovs_ovn_changes or all_branch_keys:
            print()
            print('OVS/OVN binary branches:')

        repo_for = {'OVN_BRANCH': ovn_repo, 'OVS_BRANCH': ovs_repo}

        printed_keys = set()
        if ovs_ovn_changes:
            name_w = max(len(k) for k, _, _ in ovs_ovn_changes)
            ver_w = max(len(f'{o} -> {n}') for _, o, n in ovs_ovn_changes)
            for key, old, new in ovs_ovn_changes:
                printed_keys.add(key)
                stability = [f'was: {classify_ref(old)}',
                             f'now: {classify_ref(new)}']
                attr = fmt_attribution(key, change_map)
                ver_str = f'{old} -> {new}'
                print(f'  {key:<{name_w}}  {ver_str:<{ver_w}}{attr}')
                print(f'  {"":<{name_w}}  {"; ".join(stability)}')
                if args.branch_commits and \
                        classify_ref(new) == 'branch (moving)':
                    commits = get_branch_commits(
                        repo_for[key], new, start_date, end_date)
                    _print_branch_commits(key, new, commits, name_w)

        # Unchanged moving branches requested via --branch-commits
        for key in sorted(all_branch_keys - printed_keys):
            val = end_branches.get(key, '')
            print(f'  {key}  {val} (unchanged, {classify_ref(val)})')
            if args.branch_commits:
                commits = get_branch_commits(
                    repo_for[key], val, start_date, end_date)
                _print_branch_commits(key, val, commits)


if __name__ == '__main__':
    main()
