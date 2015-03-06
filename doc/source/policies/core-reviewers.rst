Core Neutron Reviewers
======================

The `Neutron Core Reviewer Team <https://review.openstack.org/#/admin/groups/38,members>`_ is responsible
for merging changes into the following repositories:

* `openstack/neutron <https://git.openstack.org/cgit/openstack/neutron/>`_
* `openstack/neutron-fwaas <https://git.openstack.org/cgit/openstack/neutron-fwaas/>`_
* `openstack/neutron-lbaas <https://git.openstack.org/cgit/openstack/neutron-lbaas/>`_
* `openstack/neutron-vpnaas <https://git.openstack.org/cgit/openstack/neutron-vpnaas/>`_
* `openstack/python-neutronclient <https://git.openstack.org/cgit/openstack/python-neutronclient/>`_
* `openstack/neutron-specs <https://git.openstack.org/cgit/openstack/neutron-specs/>`_

While everyone is encouraged to review changes for these repositories, members of the neutron-core
gerrit group have the ability to +2/-2 and +A changes these repositories. This is responsibility
that is not to be taken lightly.

Adding or Removing Core Reviewers
---------------------------------

A new Neutron core reviewer may be proposed at anytime on the openstack-dev mailing list. Typically,
the Neutron PTL will propose a new member after discussions with the existing core reviewers. Once
a proposal has been made, five existing Neutron core reviewers must respond to the email with a +1.
Another Neutron core reviewer can vote -1 to veto the proposed new core reviewer.

The PTL may remove a Neutron core reviewer at any time. Typically when a member has decreased their
involvement with the project through a drop in reviews and participation in general project development,
the PTL will propose their removal and remove them. Please note there is no voting or vetoing of
core reviewer removal. Members who have previously been a core reviewer may be fast-tracked back into
a core reviewer role if their involvement picks back up and the existing core reviewers support their
re-instatement.

Core Reviewer Membership Expectations
-------------------------------------

Neutron core reviewers have the following expectations:

* Reasonable attendance at the weekly Neutron IRC meetings.
* Participation in Neutron discussions on the mailing list, as well as in-channel in #openstack-neutron.
* Participation in Neutron related design summit sessions at the OpenStack Summits.

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
core reviewers is important. Being able to work together with the existing Neutron core review team is critical
as well. Being a Neutron core reviewer means spending a significant amount of time with the existing Neutron
core reviewer team on IRC, the mailing list, at Summits, and in reviews. Ensuring you participate and engage
here is critical to becoming and remaining a core.
