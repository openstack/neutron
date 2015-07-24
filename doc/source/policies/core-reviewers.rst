Neutron Core Reviewers
======================

The `Neutron Core Reviewer Team
<https://review.openstack.org/#/admin/groups/38,members>`_ is responsible
for many things related to Neutron. A lot of these things include mundane
tasks such as the following:

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

The following are the current Neutron Lieutenants.

+------------------------+---------------------------+----------------------+
| Area                   | Lieutenant                | IRC nic              |
+========================+===========================+======================+
| API and DB             | Akihiro Motoki            | amotoki              |
|                        | Henry Gessau              | HenryG               |
+------------------------+---------------------------+----------------------+
| Built-In Control Plane | Kevin Benton              | kevinbenton          |
+------------------------+---------------------------+----------------------+
| Client                 | Akihiro Motoki            | amotoki              |
+------------------------+---------------------------+----------------------+
| Docs                   | Edgar Magana              | emagana              |
+------------------------+---------------------------+----------------------+
| L3                     | Carl Baldwin              | carl_baldwin         |
+------------------------+---------------------------+----------------------+
| Services               | Doug Wiegley              | dougwig              |
+------------------------+---------------------------+----------------------+
| Testing                | Assaf Muller              | amuller              |
+------------------------+---------------------------+----------------------+

Some notes on the above:

* "Built-In Control Plane" means the L2 agents, DHCP agents, SGs, metadata
  agents and ML2.
* The client includes commands installed server side.
* L3 includes the L3 agent, DVR, and IPAM.
* Services includes FWaaS, LBaaS, and VPNaaS.
* Note these areas may change as the project evolves due to code refactoring,
  new feature areas, and libification of certain pieces of code.

Neutron also consists of several plugins, drivers, and agents that are developed
effectively as sub-projects within Neutron in their own git repositories.
Lieutenants are also named for these sub-projects to identify a clear point of
contact and leader for that area.  The Lieutenant is also responsible for
updating the core review team for the sub-project's repositories.

+------------------------+---------------------------+----------------------+
| Area                   | Lieutenant                | IRC nick             |
+========================+===========================+======================+
| dragonflow             | Eran Gampel               | gampel               |
|                        | Gal Sagie                 | gsagie               |
+------------------------+---------------------------+----------------------+
| networking-l2gw        | Sukhdev Kapur             | sukhdev              |
+------------------------+---------------------------+----------------------+
| networking-midonet     | Ryu Ishimoto              | ryu_ishimoto         |
|                        | Jaume Devesa              | devvesa              |
|                        | YAMAMOTO Takashi          | yamamoto             |
+------------------------+---------------------------+----------------------+
| networking-odl         | Flavio Fernandes          | flaviof              |
|                        | Kyle Mestery              | mestery              |
+------------------------+---------------------------+----------------------+
| networking-ofagent     | YAMAMOTO Takashi          | yamamoto             |
+------------------------+---------------------------+----------------------+
| networking-ovn         | Russell Bryant            | russellb             |
+------------------------+---------------------------+----------------------+
| networking-plumgrid    | Fawad Khaliq              | fawadkhaliq          |
+------------------------+---------------------------+----------------------+
| networking-sfc         | Cathy Zhang               | cathy                |
+------------------------+---------------------------+----------------------+
| networking-vshpere     | Vivekanandan Narasimhan   | viveknarasimhan      |
+------------------------+---------------------------+----------------------+
| octavia                | German Eichberger         | xgerman              |
+------------------------+---------------------------+----------------------+
| vmware-nsx             | Gary Kotton               | garyk                |
+------------------------+---------------------------+----------------------+

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

Neutron Core Reviewer Teams
===========================

Given all of the above, Neutron has the following core reviewer teams with
responsibility over the areas of code listed below:

Neutron Core Reviewer Team
--------------------------
Neutron core reviewers have merge rights to the following git repositories:

* `openstack/neutron <https://git.openstack.org/cgit/openstack/neutron/>`_
* `openstack/python-neutronclient <https://git.openstack.org/cgit/openstack/python-neutronclient/>`_

Please note that as we adopt to the system above with core specialty in
particular areas, we expect this broad core team to shrink as people naturally
evolve into an area of specialization.

Neutron FWaaS Core Reviewer Team
--------------------------------
Neutron FWaaS core reviewers have merge rights to the following git
repositories:

* `openstack/neutron-fwaas <https://git.openstack.org/cgit/openstack/neutron-fwaas/>`_

Neutron LBaaS Core Reviewer Team
--------------------------------
Neutron LBaaS core reviewers have merge rights to the following git
repositories:

* `openstack/neutron-lbaas <https://git.openstack.org/cgit/openstack/neutron-lbaas/>`_

Neutron VPNaaS Core Reviewer Team
---------------------------------
Neutron VPNaaS core reviewers have merge rights to the following git
repositories:

* `openstack/neutron-vpnaas <https://git.openstack.org/cgit/openstack/neutron-vpnaas/>`_

Neutron Core Reviewer Teams for Plugins and Drivers
---------------------------------------------------
The plugin decomposition effort has led to having many drivers with code in
separate repositories with their own core reviewer teams. For each one of
these repositories in the following repository list, there is a core team
associated with it:

* `Neutron project team <http://governance.openstack.org/reference/projects/neutron.html>`_

These teams are also responsible for handling their own specs/RFEs/features if
they choose to use them.  However, by choosing to be a part of the Neutron
project, they submit to oversight and veto by the Neutron PTL if any issues
arise.

Neutron Specs Core Reviewer Team
--------------------------------
Neutron specs core reviewers have merge rights to the following git
repositories:

* `openstack/neutron-specs <https://git.openstack.org/cgit/openstack/neutron-specs/>`_

The Neutron specs core reviewer team is responsible for reviewing and merging
specs into the neutron-specs repository. For the Liberty release, the Specs
core reviewer team will review specs targeted to all neutron git repositories.

It's worth noting specs reviewers have the following attributes which are
potentially different than code reviewers:

* Broad understanding of cloud and networking technologies
* Broad understanding of core OpenStack projects and technologies
* An understanding of the effect approved specs have on the teams development
  capacity for each cycle

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

A new Neutron core reviewer may be proposed at anytime on the openstack-dev
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

* `30 day review stats <http://stackalytics.com/report/contribution/neutron-group/30>`_
* `60 day review stats <http://stackalytics.com/report/contribution/neutron-group/60>`_
* `90 day review stats <http://stackalytics.com/report/contribution/neutron-group/90>`_
* `180 day review stats <http://stackalytics.com/report/contribution/neutron-group/180>`_

There are soft-touch items around being a Neutron core reviewer as well.
Gaining trust with the existing Neutron core reviewers is important. Being
able to work together with the existing Neutron core reviewer team is
critical as well. Being a Neutron core reviewer means spending a significant
amount of time with the existing Neutron core reviewers team on IRC, the
mailing list, at Summits, and in reviews. Ensuring you participate and engage
here is critical to becoming and remaining a core reviewer.
