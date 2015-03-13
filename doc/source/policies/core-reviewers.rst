Neutron Core Reviewers
======================

The `Neutron Core Reviewer Team <https://review.openstack.org/#/admin/groups/38,members>`_ is responsible
for many things related to Neutron. A lot of these things include mundane tasks such as the
following:

* Ensuring the bug count is low
* Curating the gate and triaging failures
* Working on integrating shared code from projects such as Oslo
* Ensuring documentation is up to date and remains relevant
* Ensuring the level of testing for Neutron is adequate and remains relevant as features are added
* Helping new contributors with questions as they peel back the covers of Neutron
* Answering questions and participating in mailing list discussions
* Interfacing with other OpenStack teams and ensuring they are going in the same parallel direction
* Reviewing and merging code into the neutron tree

In essence, core reviewers share the following common ideals:

1. They share responsibility in the project's success.
2. They have made a long-term, recurring time investment to improve the project.
3. They spend their time doing what needs to be done to ensure the projects success, not necessarily
   what is the most interesting or fun.

Given the above, Neutron has the following core reviewer teams with responsibility over the areas of
code listed below:

Neutron Core Reviewer Team
--------------------------
Neutron core reviewers have merge rights to the following git repositories:
* `openstack/neutron <https://git.openstack.org/cgit/openstack/neutron/>`_
* `openstack/python-neutronclient <https://git.openstack.org/cgit/openstack/python-neutronclient/>`_

Neutron FWaaS Core Reviewer Team
--------------------------------
Neutron FWaaS core reviewers have merge rights to the following git repositories:
* `openstack/neutron-fwaas <https://git.openstack.org/cgit/openstack/neutron-fwaas/>`_

Neutron LBaaS Core Reviewer Team
--------------------------------
Neutron LBaaS core reviewers have merge rights to the following git repositories:
* `openstack/neutron-lbaas <https://git.openstack.org/cgit/openstack/neutron-lbaas/>`_

Neutron VPNaaS Core Reviewer Team
---------------------------------
Neutron VPNaaS core reviewers have merge rights to the following git repositories:
* `openstack/neutron-vpnaas <https://git.openstack.org/cgit/openstack/neutron-vpnaas/>`_

Neutron Specs Core Reviewer Team
--------------------------------
Neutron specs core reviewers have merge rights to the following git repositories:
* `openstack/neutron-specs <https://git.openstack.org/cgit/openstack/neutron-specs/>`_

The Neutron specs core reviewer team is responsible for reviewing and merging specs into
the neutron-specs repository. For the Liberty release, the Specs core reviewer team will
review specs targeted to all neutron git repositories.

It's worth noting specs reviewers have the following attributes which are potentially
different than code reviewers:

* Broad understanding of cloud and networking technologies
* Broad understanding of core OpenStack projects and technologies
* An understanding of the effect approved specs have on the teams development capacity
  for each cycle

Code Merge Responsibilities
===========================

While everyone is encouraged to review changes for these repositories, members of the Neutron
core reviewer group have the ability to +2/-2 and +A changes to these repositories. This is an extra
level of responsibility not to be taken lightly. Correctly merging code requires not only
understanding the code itself, but also how the code affects things like documentation, testing,
and interactions with other projects. It also means you pay attention to release milestones and
understand if a patch you're merging is marked for the release, especially critical during the
feature freeze.

The bottom line here is merging code is a responsibility Neutron core reviewers have.

Adding or Removing Core Reviewers
---------------------------------

A new Neutron core reviewer may be proposed at anytime on the openstack-dev mailing list. Typically,
the Neutron PTL will propose a new member after discussions with the existing core reviewers. Once
a proposal has been made, five existing Neutron core reviewers must respond to the email with a +1.
If the member is being added to a core reviewer team with less than five members, a simple majority
will be used to determine if the vote is successful. Another Neutron core reviewer can vote -1 to
veto the proposed new core reviewer.

The PTL may remove a Neutron core reviewer at any time. Typically when a member has decreased their
involvement with the project through a drop in reviews and participation in general project development,
the PTL will propose their removal and remove them. Please note there is no voting or vetoing of
core reviewer removal. Members who have previously been a core reviewer may be fast-tracked back into
a core reviewer role if their involvement picks back up and the existing core reviewers support their
re-instatement.

Neutron Core Reviewer Membership Expectations
---------------------------------------------

Neutron core reviewers have the following expectations:

* Reasonable attendance at the weekly Neutron IRC meetings.
* Participation in Neutron discussions on the mailing list, as well as in-channel in #openstack-neutron.
* Participation in Neutron related design summit sessions at the OpenStack Summits.

Please note in-person attendance at design summits, mid-cycles, and other code sprints is not a requirement
to be a Neutron core reviewer. The Neutron team will do its best to facilitate virtual attendance at all events.
Travel is not to be taken lightly, and we realize the costs involved for those who partake in attending
these events.

In addition to the above, code reviews are the most important requirement of Neutron core reviewers.
Neutron follows the documented OpenStack `code review guidelines <https://wiki.openstack.org/wiki/ReviewChecklist>`_.
We encourage all people to review Neutron patches, but core reviewers are required to maintain a level of
review numbers relatively close to other core reviewers. There are no hard statistics around code review
numbers, but in general we use 30, 60, 90 and 180 day stats when examining review stats.

* `30 day review stats <http://stackalytics.com/report/contribution/neutron-group/30>`_
* `60 day review stats <http://stackalytics.com/report/contribution/neutron-group/60>`_
* `90 day review stats <http://stackalytics.com/report/contribution/neutron-group/90>`_
* `180 day review stats <http://stackalytics.com/report/contribution/neutron-group/180>`_

There are soft-touch items around being a Neutron core reviewer as well. Gaining trust with the existing Neutron
core reviewers is important. Being able to work together with the existing Neutron core reviewer team is critical
as well. Being a Neutron core reviewer means spending a significant amount of time with the existing Neutron
core reviewers team on IRC, the mailing list, at Summits, and in reviews. Ensuring you participate and engage
here is critical to becoming and remaining a core reviewer.
