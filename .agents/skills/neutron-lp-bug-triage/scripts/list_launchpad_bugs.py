#!/usr/bin/env python3

# Copyright 2026 Red Hat, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""List Launchpad bugs for a project within an inclusive day range."""

import argparse
import datetime
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

LAUNCHPAD_API = 'https://api.launchpad.net/1.0'
VALID_STATUSES = [
    'New', 'Incomplete', 'Incomplete (with response)',
    'Incomplete (without response)', 'Opinion', 'Invalid', "Won't Fix",
    'Expired', 'Confirmed', 'Triaged', 'In Progress', 'Fix Committed',
    'Fix Released',
]
VALID_IMPORTANCES = [
    'Undecided', 'Critical', 'High', 'Medium', 'Low', 'Wishlist',
]
GERRIT_URL = 'https://review.opendev.org'
TITLE_RE = re.compile(r'^Bug #\d+ in [^:]+: "(.*)"$')
PROPOSED_PATCH_RE = re.compile(
    r'(?:Fix|Related fix) proposed.*\nReview: (https?://\S+)',
    re.IGNORECASE,
)
ABANDONED_PATCH_RE = re.compile(
    r'Change abandoned.*\nReview: (https?://\S+)',
    re.IGNORECASE,
)
MERGED_PATCH_RE = re.compile(
    r'(?:Fix merged|Change merged).*?\nReview: (https?://\S+)',
    re.IGNORECASE,
)


def _parse_date(value):
    try:
        return datetime.date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f'invalid date {value!r}; use YYYY-MM-DD'
        ) from exc


def _api_get(url):
    try:
        with urllib.request.urlopen(url) as response:  # noqa: S310
            return json.load(response)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode('utf-8', errors='replace')
        raise RuntimeError(
            f'API request failed ({exc.code}) for {url}: {body}'
        ) from exc


def _build_search_url(project, start_date, end_date, status=None,
                      importance=None):
    # Launchpad treats created_before as exclusive, so add one day to make
    # the end date inclusive.
    params = {
        'ws.op': 'searchTasks',
        'order_by': 'datecreated',
        'created_since': start_date.isoformat(),
        'created_before': (end_date + datetime.timedelta(days=1)).isoformat(),
    }
    if status:
        params['status'] = status
    if importance:
        params['importance'] = importance
    query = urllib.parse.urlencode(params, doseq=True)
    return f'{LAUNCHPAD_API}/{project}?{query}'


def _clean_title(title):
    match = TITLE_RE.match(title)
    if match:
        return match.group(1)
    return title


def _resolve_person_name(person_cache, person_link):
    if not person_link:
        return None
    if person_link in person_cache:
        return person_cache[person_link]
    person = _api_get(person_link)
    name = person.get('display_name') or person.get('name')
    person_cache[person_link] = name
    return name


def _gerrit_search(query, timeout=60):
    url = f'{GERRIT_URL}/changes/?' + urllib.parse.urlencode({'q': query})
    request = urllib.request.Request(  # noqa: S310
        url, headers={'Accept': 'application/json'})
    try:
        with urllib.request.urlopen(request,  # noqa: S310
                                    timeout=timeout) as response:
            raw = response.read().decode('utf-8')
    except urllib.error.URLError:
        return []

    if raw.startswith(")]}'"):
        raw = raw[4:]
    if not raw.strip():
        return []
    return json.loads(raw)


def _gerrit_change_url(change):
    number = change.get('_number')
    project = change.get('project', 'openstack/neutron')
    return f'{GERRIT_URL}/c/{project}/+/{number}'


def _find_active_gerrit_patches(bug_id):
    query = f'message:{bug_id} status:open'
    changes = _gerrit_search(query)
    patches = []
    for change in changes:
        number = change.get('_number')
        if not number:
            continue
        patches.append({
            'number': number,
            'status': change.get('status'),
            'subject': change.get('subject'),
            'url': _gerrit_change_url(change),
        })
    return patches


def _find_active_patches_from_messages(bug_id):
    url = f'{LAUNCHPAD_API}/bugs/{bug_id}/messages?ws.size=100'
    data = _api_get(url)
    proposed = {}
    inactive = set()

    for message in data.get('entries', []):
        content = message.get('content') or ''
        for match in PROPOSED_PATCH_RE.finditer(content):
            proposed[match.group(1).rstrip('.,)')] = {
                'url': match.group(1).rstrip('.,)'),
                'source': 'launchpad-message',
            }
        for match in ABANDONED_PATCH_RE.finditer(content):
            inactive.add(match.group(1).rstrip('.,)'))
        for match in MERGED_PATCH_RE.finditer(content):
            inactive.add(match.group(1).rstrip('.,)'))

    return [
        patch for url, patch in proposed.items()
        if url not in inactive
    ]


def _find_active_patches(bug_id):
    gerrit_patches = _find_active_gerrit_patches(bug_id)
    if gerrit_patches:
        return gerrit_patches

    message_patches = _find_active_patches_from_messages(bug_id)
    return [
        {
            'url': patch['url'],
            'source': patch['source'],
        }
        for patch in message_patches
    ]


def _fetch_bug_tasks(url, enrich=False, person_cache=None):
    if person_cache is None:
        person_cache = {}

    while url:
        data = _api_get(url)
        for entry in data.get('entries', []):
            bug = {
                'id': entry['bug_link'].rsplit('/', 1)[-1],
                'created': entry['date_created'],
                'status': entry['status'],
                'importance': entry['importance'],
                'title': _clean_title(entry['title']),
                'url': entry['web_link'],
            }
            if enrich:
                assignee = _resolve_person_name(
                    person_cache, entry.get('assignee_link'))
                bug['assignee'] = assignee or 'Unassigned'
                bug['active_patches'] = _find_active_patches(bug['id'])
            yield bug
        url = data.get('next_collection_link')


def fetch_bugs(project, start_date, end_date, status=None,
               importance=None, enrich=False):
    if start_date > end_date:
        raise ValueError(
            f'start date {start_date} must not be after end date {end_date}'
        )

    url = _build_search_url(project, start_date, end_date, status=status,
                            importance=importance)
    return list(_fetch_bug_tasks(url, enrich=enrich))


def _print_text(bugs, start_date, end_date, project):
    print(
        f'{len(bugs)} bug(s) in {project} created from '
        f'{start_date} through {end_date} (inclusive)'
    )
    for bug in bugs:
        created = bug['created'].split('T', 1)[0]
        line = (
            f"{bug['id']}\t{created}\t{bug['status']}\t"
            f"{bug['importance']}\t{bug['title']}"
        )
        if 'assignee' in bug:
            line = f"{line}\t{bug['assignee']}"
        print(line)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            'List Launchpad bugs for a project created within a day range. '
            'Both start and end dates are inclusive.'
        )
    )
    parser.add_argument(
        '--start', required=True, type=_parse_date,
        help='First day to include (YYYY-MM-DD)',
    )
    parser.add_argument(
        '--end', required=True, type=_parse_date,
        help='Last day to include (YYYY-MM-DD)',
    )
    parser.add_argument(
        '--project', default='neutron',
        help='Launchpad project name (default: neutron)',
    )
    parser.add_argument(
        '--status', nargs='+', choices=VALID_STATUSES, metavar='STATUS',
        help='Launchpad status filter; one or more of: %(choices)s. '
             'Quote multi-word values, e.g. --status New "In Progress"',
    )
    parser.add_argument(
        '--importance', nargs='+', choices=VALID_IMPORTANCES,
        metavar='IMPORTANCE',
        help='Launchpad importance filter; one or more of: %(choices)s',
    )
    parser.add_argument(
        '--enrich', action='store_true',
        help='Resolve assignee and detect active Gerrit patches per bug',
    )
    parser.add_argument(
        '--json', action='store_true',
        help='Print results as JSON',
    )
    args = parser.parse_args(argv)

    try:
        bugs = fetch_bugs(
            args.project, args.start, args.end,
            status=args.status, importance=args.importance,
            enrich=args.enrich)
    except (RuntimeError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(bugs, indent=2))
    else:
        _print_text(bugs, args.start, args.end, args.project)
    return 0


if __name__ == '__main__':
    sys.exit(main())
