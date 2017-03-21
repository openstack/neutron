#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
"""Unassigns assignee from neutron/network bug, adds message and tag.

If you get the following exception, you need X11 and python-dbus installed:
RuntimeError: No recommended backend was available. Install
the keyrings.alt package if you want to use the non-recommended
backends. See README.rst for details.

"""


import sys

from launchpadlib.launchpad import Launchpad


MSG_BODY = "\
This bug has had a related patch abandoned and has been automatically \
un-assigned due to inactivity. Please re-assign yourself if you are \
continuing work or adjust the state as appropriate if it is no longer valid."


def unassign(bug_num):
    launchpad = Launchpad.login_with('neutron', 'production')
    b = launchpad.bugs[bug_num]
    for task in b.bug_tasks:
        if ('neutron' not in task.bug_target_name and
                'network' not in task.bug_target_name):
            # try not to interfere with non-neutron projects too much
            continue
        task.assignee = None
        if task.status == "In Progress":
            task.status = 'New'
        task.lp_save()
    b.tags = b.tags + ['timeout-abandon']
    b.newMessage(content=MSG_BODY, subject='auto-abandon-script')
    b.lp_save()


if __name__ == '__main__':
    unassign(int(sys.argv[1]))
