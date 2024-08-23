.. _neutron_teams:

==============
Team Structure
==============

Neutron Core Reviewers
======================

The `Neutron Core Reviewer Team <https://review.opendev.org/#/admin/groups/38,members>`_
is responsible for many things related to Neutron. A lot of these things
include mundane tasks such as the following:

* Ensuring the bug count is low
* Curating the gate and triaging failures
* Working on integrating shared code from projects such as Oslo
* Ensuring documentation is up to date and remains relevant
* Ensuring the level of testing for Neutron is adequate and remains relevant
  as features are added
* Helping new contributors with questions as they peel back the covers of
  Neutron
* Answering questions and participating in mailing list discussions
* Interfacing with other OpenStack teams and ensuring they are going in the
  same parallel direction
* Reviewing and merging code into the neutron tree

In essence, core reviewers share the following common ideals:

1. They share responsibility in the project's success.
2. They have made a long-term, recurring time investment to improve the
   project.
3. They spend their time doing what needs to be done to ensure the projects
   success, not necessarily what is the most interesting or fun.

A core reviewer's responsibility doesn't end up with merging code. The above
lists are adding context around these responsibilities.

.. _core-review-hierarchy:

Core Review Hierarchy
---------------------

As Neutron has grown in complexity, it has become impossible for any one
person to know enough to merge changes across the entire codebase. Areas of
expertise have developed organically, and it is not uncommon for existing
cores to defer to these experts when changes are proposed. Existing cores
should be aware of the implications when they do merge changes outside the
scope of their knowledge. It is with this in mind we propose a new system
built around Lieutenants through a model of trust.

In order to scale development and responsibility in Neutron, we have adopted
a Lieutenant system. The PTL is the leader of the Neutron project, and
ultimately responsible for decisions made in the project. The PTL has
designated Lieutenants in place to help run portions of the Neutron project.
The Lieutenants are in charge of their own areas, and they can propose core
reviewers for their areas as well. The core reviewer addition and removal
polices are in place below. The Lieutenants for each system, while responsible
for their area, ultimately report to the PTL. The PTL may opt to have regular
one on one meetings with the lieutenants. The PTL will resolve disputes in
the project that arise between areas of focus, core reviewers, and other
projects. Please note Lieutenants should be leading their own area of focus,
not doing all the work themselves.

As was mentioned in the previous section, a core's responsibilities do not
end with merging code. They are responsible for bug triage and gate issues
among other things. Lieutenants have an increased responsibility to ensure
gate and bug triage for their area of focus is under control.

Neutron Lieutenants
~~~~~~~~~~~~~~~~~~~

The following are the current Neutron Lieutenants.

+------------------------+---------------------------+----------------------+
| Area                   | Lieutenant                | IRC nick             |
+========================+===========================+======================+
| API                    | Akihiro Motoki            | amotoki              |
|                        +---------------------------+----------------------+
|                        | Slawomir Kaplonski        | slaweq               |
+------------------------+---------------------------+----------------------+
| DB                     | Rodolfo Alonso Hernandez  | ralonsoh             |
+------------------------+---------------------------+----------------------+
| Built-In Control Plane | Miguel Lavalle            | mlavalle             |
+------------------------+---------------------------+----------------------+
| Client                 | Akihiro Motoki            | amotoki              |
|                        +---------------------------+----------------------+
|                        | Slawomir Kaplonski        | slaweq               |
|                        +---------------------------+----------------------+
|                        | Lajos Katona              | lajoskatona          |
+------------------------+---------------------------+----------------------+
| Docs                   | Akihiro Motoki            | amotoki              |
|                        +---------------------------+----------------------+
|                        | Lajos Katona              | lajoskatona          |
+------------------------+---------------------------+----------------------+
| Infra                  | Rodolfo Alonso Hernandez  | ralonsoh             |
|                        +---------------------------+----------------------+
|                        | Jens Harbott              | frickler             |
+------------------------+---------------------------+----------------------+
| L3                     | Miguel Lavalle            | mlavalle             |
|                        +---------------------------+----------------------+
|                        | Yulong Liu                | liuyulong            |
+------------------------+---------------------------+----------------------+
| Testing                | Lajos Katona              | lajoskatona          |
|                        +---------------------------+----------------------+
|                        | Slawomir Kaplonski        | slaweq               |
+------------------------+---------------------------+----------------------+

Some notes on the above:

* "Built-In Control Plane" means the L2 agents, DHCP agents, SGs, metadata
  agents and ML2.
* The client includes commands installed server side.
* L3 includes the L3 agent, DVR, Dynamic routing and IPAM.
* Note these areas may change as the project evolves due to code refactoring,
  new feature areas, and libification of certain pieces of code.
* Infra means interactions with infra from a neutron perspective

.. _subproject_lieutenants:

Sub-project Lieutenants
~~~~~~~~~~~~~~~~~~~~~~~

Neutron also consists of several plugins, drivers, and agents that are
developed effectively as sub-projects within Neutron in their own git
repositories.
Lieutenants are also named for these sub-projects to identify a clear point of
contact and leader for that area.  The Lieutenant is also responsible for
updating the core review team for the sub-project's repositories.

+-------------------------+-----------------------------+-------------------+
| Area                    | Lieutenant                  | IRC nick          |
+=========================+=============================+===================+
| networking-bgpvpn /     | Lajos Katona                | lajoskatona       |
| networking-bagpipe      +-----------------------------+-------------------+
|                         | Thomas Morin                | tmorin            |
+-------------------------+-----------------------------+-------------------+
| neutron-dynamic-routing | Tobias Urdin                | tobias-urdin      |
|                         +-----------------------------+-------------------+
|                         | Jens Harbott                | frickler          |
+-------------------------+-----------------------------+-------------------+
| neutron-fwaas           | ZhouHeng                    | zhouhenglc        |
+-------------------------+-----------------------------+-------------------+
| neutron-vpnaas          | YAMAMOTO Takashi            | yamamoto          |
|                         +-----------------------------+-------------------+
|                         | Dongcan Ye                  | yedongcan         |
+-------------------------+-----------------------------+-------------------+
| networking-sfc          | Dharmendra Kushwaha         | dkushwaha         |
+-------------------------+-----------------------------+-------------------+
| ovn-octavia-provider    | Luis Tomas Bolivar          | ltomasbo          |
|                         +-----------------------------+-------------------+
|                         | Fernando Royo               | froyo             |
+-------------------------+-----------------------------+-------------------+
| ovsdbapp                | Terry Wilson                | otherwiseguy      |
+-------------------------+-----------------------------+-------------------+
| os-ken                  | Rodolfo Alonso              | ralonsoh          |
+-------------------------+-----------------------------+-------------------+

Existing Core Reviewers
-----------------------

Existing core reviewers have been reviewing code for a varying degree of
cycles. With the new plan of Lieutenants and ownership, it's fair to try to
understand how they fit into the new model. Existing core reviewers seem
to mostly focus in particular areas and are cognizant of their own strengths
and weaknesses. These members may not be experts in all areas, but know their
limits, and will not exceed those limits when reviewing changes outside their
area of expertise. The model is built on trust, and when that trust is broken,
responsibilities will be taken away.

Lieutenant Responsibilities
---------------------------

In the hierarchy of Neutron responsibilities, Lieutenants are expected to
partake in the following additional activities compared to other core
reviewers:

* Ensuring feature requests for their areas have adequate testing and
  documentation coverage.
* Gate triage and resolution. Lieutenants are expected to work to keep the
  Neutron gate running smoothly by triaging issues, filing elastic recheck
  queries, and closing gate bugs.
* Triaging bugs for the specific areas.

Neutron Teams
=============

Given all of the above, Neutron has a number of core reviewer teams with
responsibility over the areas of code listed below:

Neutron Core Reviewer Team
--------------------------
`Neutron core reviewers <https://review.opendev.org/#/admin/groups/38,members>`_ have
merge rights to the following git repositories:

* `openstack/neutron <https://opendev.org/openstack/neutron/>`_
* `openstack/python-neutronclient <https://opendev.org/openstack/python-neutronclient/>`_

Please note that as we adopt to the system above with core specialty in
particular areas, we expect this broad core team to shrink as people naturally
evolve into an area of specialization.

Core Reviewer Teams for Plugins and Drivers
-------------------------------------------
The plugin decomposition effort has led to having many drivers with code in
separate repositories with their own core reviewer teams. For each one of
these repositories in the following repository list, there is a core team
associated with it:

* `Neutron project team <https://governance.openstack.org/tc/reference/projects/neutron.html>`_

These teams are also responsible for handling their own specs/RFEs/features if
they choose to use them.  However, by choosing to be a part of the Neutron
project, they submit to oversight and veto by the Neutron PTL if any issues
arise.

.. _specs-core-reviewer-team:

Neutron Specs Core Reviewer Team
--------------------------------
Neutron `specs core reviewers <https://review.opendev.org/#/admin/groups/314,members>`_
have +2 rights to the following git repositories:

* `openstack/neutron-specs <https://opendev.org/openstack/neutron-specs/>`_

The Neutron specs core reviewer team is responsible for reviewing specs
targeted to all Neutron git repositories (Neutron + Advanced Services).
It is worth noting that specs reviewers have the following attributes which
are potentially different than code reviewers:

* Broad understanding of cloud and networking technologies
* Broad understanding of core OpenStack projects and technologies
* An understanding of the effect approved specs have on the teams development
  capacity for each cycle

Specs core reviewers may match core members of the above mentioned groups, but
the group can be extended to other individuals, if required.

.. _drivers_team:

Drivers Team
------------

The `drivers team <https://review.opendev.org/#/admin/groups/464,members>`_ is
the group of people who have full rights to the specs repo. This team, which
matches
`Launchpad Neutron Drivers team <https://launchpad.net/~neutron-drivers>`_, is
instituted to ensure a consistent architectural vision for the Neutron
project, and to continue to disaggregate and share the responsibilities of
the Neutron PTL. The team is in charge of reviewing and commenting on
:ref:`RFEs <request-for-feature-enhancement>`,
and working with specification contributors to provide guidance on the process
that govern contributions to the Neutron project as a whole. The team
`meets regularly <https://wiki.openstack.org/wiki/Meetings/NeutronDrivers>`_
to go over RFE's and discuss the project roadmap. Anyone is welcome to join
and/or read the meeting notes.

Release Team
------------

The `release team <https://review.opendev.org/#/admin/groups/150,members>`_ is
a group of people with some additional gerrit permissions primarily aimed at
allowing release management of Neutron sub-projects. These permissions include:

* Ability to push signed tags to sub-projects whose releases are managed by the
  Neutron release team as opposed to the OpenStack release team.
* Ability to push merge commits for Neutron or other sub-projects.
* Ability to approve changes in all Neutron git repositories.  This is required
  as the team needs to be able to quickly unblock things if needed, especially
  at release time.

Code Merge Responsibilities
===========================

While everyone is encouraged to review changes for these repositories, members
of the Neutron core reviewer group have the ability to +2/-2 and +A changes to
these repositories. This is an extra level of responsibility not to be taken
lightly. Correctly merging code requires not only understanding the code
itself, but also how the code affects things like documentation, testing, and
interactions with other projects. It also means you pay attention to release
milestones and understand if a patch you're merging is marked for the release,
especially critical during the feature freeze.

The bottom line here is merging code is a responsibility Neutron core reviewers
have.

Adding or Removing Core Reviewers
---------------------------------

A new Neutron core reviewer may be proposed at anytime on the openstack-discuss
mailing list. Typically, the Lieutenant for a given area will propose a new
core reviewer for their specific area of coverage, though the Neutron PTL may
propose new core reviewers as well. The proposal is typically made after
discussions with existing core reviewers. Once a proposal has been made,
three existing Neutron core reviewers from the Lieutenant's area of focus must
respond to the email with a +1. If the member is being added by a Lieutenant
from an area of focus with less than three members, a simple majority will be
used to determine if the vote is successful. Another Neutron core reviewer
from the same area of focus can vote -1 to veto the proposed new core
reviewer. The PTL will mediate all disputes for core reviewer additions.

The PTL may remove a Neutron core reviewer at any time. Typically when a
member has decreased their involvement with the project through a drop in
reviews and participation in general project development, the PTL will propose
their removal and remove them. Please note there is no voting or vetoing of
core reviewer removal. Members who have previously been a core reviewer may be
fast-tracked back into a core reviewer role if their involvement picks back up
and the existing core reviewers support their re-instatement.

Neutron Core Reviewer Membership Expectations
---------------------------------------------

Neutron core reviewers have the following expectations:

* Reasonable attendance at the weekly Neutron IRC meetings.
* Participation in Neutron discussions on the mailing list, as well as
   in-channel in #openstack-neutron.
* Participation in Neutron related design summit sessions at the OpenStack
  Summits.

Please note in-person attendance at design summits, mid-cycles, and other code
sprints is not a requirement to be a Neutron core reviewer. The Neutron team
will do its best to facilitate virtual attendance at all events. Travel is not
to be taken lightly, and we realize the costs involved for those who partake
in attending these events.

In addition to the above, code reviews are the most important requirement of
Neutron core reviewers. Neutron follows the documented OpenStack `code review
guidelines <https://wiki.openstack.org/wiki/ReviewChecklist>`_. We encourage
all people to review Neutron patches, but core reviewers are required to
maintain a level of review numbers relatively close to other core reviewers.
There are no hard statistics around code review numbers, but in general we
use 30, 60, 90 and 180 day stats when examining review stats.

* `30 day review stats <https://www.stackalytics.io/report/contribution?module=neutron-group&project_type=openstack&days=30>`_
* `60 day review stats <https://www.stackalytics.io/report/contribution?module=neutron-group&project_type=openstack&days=60>`_
* `90 day review stats <https://www.stackalytics.io/report/contribution?module=neutron-group&project_type=openstack&days=90>`_
* `180 day review stats <https://www.stackalytics.io/report/contribution?module=neutron-group&project_type=openstack&days=180>`_

There are soft-touch items around being a Neutron core reviewer as well.
Gaining trust with the existing Neutron core reviewers is important. Being
able to work together with the existing Neutron core reviewer team is
critical as well. Being a Neutron core reviewer means spending a significant
amount of time with the existing Neutron core reviewers team on IRC, the
mailing list, at Summits, and in reviews. Ensuring you participate and engage
here is critical to becoming and remaining a core reviewer.
