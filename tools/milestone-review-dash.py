#!/usr/bin/env python

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

import argparse
import sys
import urllib2
import yaml

from launchpadlib.launchpad import Launchpad


def is_milestone_valid(project, name):
    milestone_names = []
    for s in project.active_milestones:
        milestone_names.append(s.name)
        if name == s.name:
            return True
    print("No active milestone found")
    print("List of active milestones %s" % milestone_names)
    return False


def get_current_milestone(project):
    series = project.get_timeline()['entries']
    current_milestone = ""
    for s in series:
        if s['is_development_focus']:
            for landmark in s['landmarks']:
                #landmark with a date set are past milestones
                if not landmark['date']:
                    if (landmark['name'] < current_milestone or
                        not current_milestone):
                        current_milestone = landmark['name']
    return current_milestone


def _search_task(project, **kwargs):
    bugs = project.searchTasks(**kwargs)
    if not bugs:
        return
    gerrit_query = "("
    for b in bugs:
        gerrit_query += ("message:%d OR " % b.bug.id)
    gerrit_query = gerrit_query[:-4]
    gerrit_query += ")\n\n"
    return gerrit_query


def get_approved_rfe_query(project):
    return _search_task(project, **{'tags': ['rfe-approved']})


def get_critical_bugs_query(project):
    return _search_task(project,
        **{'status': ["In Progress"], 'importance': ["Critical"]})


def get_high_bugs_query(project):
    return _search_task(project,
        **{'status': ["In Progress"], 'importance': ["High"]})


def get_specs_query(project, milestone):
    query = "("
    for s in project.valid_specifications:
        if s.milestone is not None:
            if s.milestone.name == milestone:
                query += ("topic:bp/%s OR " % s.name)
    if query == "(":
        # no blueprint was found
        return
    query = query[:-4]
    query += ")\n"
    return query


def write_section(f, section_name, query):
    print(section_name)
    if query:
        f.write("[section \"")
        f.write(section_name)
        f.write("\"]\n")
        f.write("query = ")
        f.write(query)
        print(query)
    else:
        print("No result found\n")


def write_queries_for_project(f, project, milestone):
    query = get_approved_rfe_query(project)
    section_name = "Approved RFE %s" % project.name
    write_section(f, section_name, query)

    query = get_critical_bugs_query(project)
    section_name = "Critical Bugs %s" % project.name
    write_section(f, section_name, query)

    query = get_high_bugs_query(project)
    section_name = "High Bugs %s" % project.name
    write_section(f, section_name, query)

    query = get_specs_query(project, milestone)
    section_name = "Blueprints %s" % project.name
    write_section(f, section_name, query)


def get_stadium_projects():
    data = urllib2.urlopen("http://git.openstack.org/cgit/openstack/"
                           "governance/plain/reference/projects.yaml")
    governance = yaml.load(data)
    return governance["neutron"]["deliverables"].keys()


parser = argparse.ArgumentParser(
    description='Create dashboard for critical/high bugs, approved rfe and'
                ' blueprints. A .dash file will be created in the current'
                ' folder that you can serve as input for gerrit-dash-creator.'
                ' The output of the script can be used to query Gerrit'
                ' directly.')
parser.add_argument('-m', '--milestone', type=str,
                    help='The release milestone')
parser.add_argument('-o', '--output', type=str, help='Output file')

cachedir = "~/.launchpadlib/cache/"
launchpad = Launchpad.login_anonymously('just testing', 'production', cachedir,
                                        version="devel")
neutron = launchpad.projects['neutron']
neutron_client = launchpad.projects['python-neutronclient']

args = parser.parse_args()
if args.milestone:
    milestone = args.milestone
    if not is_milestone_valid(neutron, milestone):
        sys.exit()
else:
    milestone = get_current_milestone(neutron)
if args.output:
    file_name = args.output
else:
    file_name = milestone + '.dash'


with open(file_name, 'w') as f:
    title = "[dashboard]\ntitle = Neutron %s Review Inbox\n" % milestone
    f.write(title)
    f.write("description = Review Inbox\n")
    f.write("foreach = (")
    projects_query = [
        "project:openstack/%s" % p for p in get_stadium_projects()
    ]
    f.write(' OR '.join(projects_query))
    f.write(") status:open NOT owner:self "
            "NOT label:Workflow<=-1 "
            "NOT label:Code-Review>=-2,self branch:master\n")
    f.write("\n")

    print("Querying Launchpad, this might take a while...")
    write_queries_for_project(f, neutron, milestone)
    write_queries_for_project(f, neutron_client, milestone)
