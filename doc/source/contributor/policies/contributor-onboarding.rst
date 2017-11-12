Contributor Onboarding
======================

For new contributors, the following are useful onboarding information.

Contributing to Neutron
-----------------------

Work within Neutron is discussed on the openstack-dev mailing list, as well as in the
#openstack-neutron IRC channel. While these are great channels for engaging Neutron,
the bulk of discussion of patches and code happens in gerrit itself.

With regards to gerrit, code reviews are a great way to learn about the project. There
is also a list of `low or wishlist <https://bugs.launchpad.net/neutron/+bugs?field.searchtext=&orderby=-importance&field.status%3Alist=NEW&field.status%3Alist=CONFIRMED&field.status%3Alist=TRIAGED&field.status%3Alist=INPROGRESS&field.status%3Alist=FIXCOMMITTED&field.status%3Alist=INCOMPLETE_WITH_RESPONSE&field.status%3Alist=INCOMPLETE_WITHOUT_RESPONSE&field.importance%3Alist=LOW&field.importance%3Alist=WISHLIST&assignee_option=any&field.assignee=&field.bug_reporter=&field.bug_commenter=&field.subscriber=&field.structural_subscriber=&field.tag=&field.tags_combinator=ANY&field.has_cve.used=&field.omit_dupes.used=&field.omit_dupes=on&field.affects_me.used=&field.has_patch.used=&field.has_branches.used=&field.has_branches=on&field.has_no_branches.used=&field.has_no_branches=on&field.has_blueprints.used=&field.has_blueprints=on&field.has_no_blueprints.used=&field.has_no_blueprints=on&search=Search>`_ priority bugs which are ideal for a new contributor to take
on. If you haven't done so you should setup a Neutron development environment so you
can actually run the code. Devstack is the usual convenient environment to setup such
an environment. See `devstack.org <http://devstack.org/>`_ or `NeutronDevstack <https://wiki.openstack.org/wiki/NeutronDevstack#Basic_Setup>`_
for more information on using Neutron with devstack.

Helping with documentation can also be a useful first step for a newcomer.
Here is a list of tagged documentation and API reference bugs:

* `Documentation bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=doc>`_
* `Api-ref bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=api-ref>`_

IRC Information and Etiquette
-----------------------------

The main IRC channel for Neutron is #openstack-neutron. We also utilize #openstack-lbaas
for LBaaS specific discussions. The weekly meeting is documented in the `list of meetings <https://wiki.openstack.org/wiki/Meetings#OpenStack_Networking_.28Neutron.29>`_ wiki page.
