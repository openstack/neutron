============================
So You Want to Contribute...
============================

For general information on contributing to OpenStack, please check out the
`contributor guide <https://docs.openstack.org/contributors/>`_ to get started.
It covers all the basics that are common to all OpenStack projects: the
accounts you need, the basics of interacting with our Gerrit review system,
how we communicate as a community, etc.

Below will cover the more project specific information you need to get started
with Neutron.

Communication
~~~~~~~~~~~~~~
.. This would be a good place to put the channel you chat in as a project; when/
   where your meeting is, the tags you prepend to your ML threads, etc.

- IRC channel: #openstack-neutron
- Mailing list's prefix: [neutron]
- Team Meeting:

  This is general Neutron team meeting. The discussion in this meeting is about
  all things related to the Neutron project, like community goals, progress
  with blueprints, bugs, etc. There is also ``On Demand Agenda`` at the end of
  this meeting, where anyone can add a topic to discuss with the Neutron team.

  - time: http://eavesdrop.openstack.org/#Neutron_Team_Meeting
  - agenda: https://wiki.openstack.org/wiki/Network/Meetings

- Drivers team meeting:

  This is the meeting where Neutron drivers discuss about new RFEs.

  - time: http://eavesdrop.openstack.org/#Neutron_drivers_Meeting
  - agenda: https://wiki.openstack.org/wiki/Meetings/NeutronDrivers

- Neutron CI team meeting:

  This is the meeting where upstream CI issues are discussed every week. If
  You are interested in helping our CI to be green, that's good place to join
  and help.

  - time: http://eavesdrop.openstack.org/#Neutron_CI_team
  - agenda: https://etherpad.openstack.org/p/neutron-ci-meetings


Contacting the Core Team
~~~~~~~~~~~~~~~~~~~~~~~~~
.. This section should list the core team, their irc nicks, emails, timezones
   etc. If all this info is maintained elsewhere (i.e. a wiki), you can link
   to that instead of enumerating everyone here.

The list of current Neutron core reviewers is available on `gerrit
<https://review.opendev.org/#/admin/groups/38,members>`_.
Overall structure of Neutron team is available in
:ref:`Neutron teams<neutron_teams>`.

New Feature Planning
~~~~~~~~~~~~~~~~~~~~
.. This section is for talking about the process to get a new feature in. Some
   projects use blueprints, some want specs, some want both! Some projects
   stick to a strict schedule when selecting what new features will be reviewed
   for a release.

Neutron team uses ``RFE (Request for Enhancements)`` to propose new features.
RFE should be submitted as a Launchpad bug first (see section
:ref:`reporting_a_bug`). The title of RFE bug should starts with ``[RFE]`` tag.
Such RFEs need to be discussed and approved by the :ref:`Neutron drivers
team<drivers_team>`. In some cases an additional spec proposed to the `Neutron
specs <https://opendev.org/openstack/neutron-specs>`_ repo may be necessary.
The complete process is described in detail in :ref:`Blueprints
guide<neutron_blueprints>`.

Task Tracking
~~~~~~~~~~~~~~
.. This section is about where you track tasks- launchpad? storyboard? is
   there more than one launchpad project? What's the name of the project group
   in storyboard?

We track our tasks in `Launchpad <https://bugs.launchpad.net/neutron>`__.
If you're looking for some smaller, easier work item to pick up and get started
on, search for the `Low hanging fruit
<https://bugs.launchpad.net/neutron/+bugs?field.tag=low-hanging-fruit>`_ tag.
List of all official tags which Neutron team is using is available on
:ref:`bugs<neutron_bugs>`.
Every week, one of our team members is the :ref:`bug
deputy<neutron_bug_deputy>` and at the end of the week such person usually
sends report about new bugs to the mailing list
openstack-discuss@lists.openstack.org or talks about it on our team meeting.
This is also good place to look for some work to do.

.. _reporting_a_bug:

Reporting a Bug
~~~~~~~~~~~~~~~
.. Pretty self explanatory section, link directly to where people should
   report bugs for your project.

You found an issue and want to make sure we are aware of it? You can do so on
`Launchpad <https://bugs.launchpad.net/neutron/+filebug>`__.
More info about Launchpad usage can be found on `OpenStack docs page
<https://docs.openstack.org/contributors/common/task-tracking.html#launchpad>`_.

Getting Your Patch Merged
~~~~~~~~~~~~~~~~~~~~~~~~~
.. This section should have info about what it takes to get something merged.
   Do you require one or two +2's before +W? Do some of your repos require
   unit test changes with all patches? etc.

All changes proposed to the Neutron or one of the Neutron stadium projects
require two +2 votes from Neutron core reviewers before one of the core
reviewers can approve patch by giving ``Workflow +1`` vote. More detailed
guidelines for reviewers of Neutron patches are available at
:ref:`Code reviews guide<code_review>`.


Project Team Lead Duties
~~~~~~~~~~~~~~~~~~~~~~~~
.. this section is where you can put PTL specific duties not already listed in
   the common PTL guide (linked below)  or if you already have them written
   up elsewhere, you can link to that doc here.

Neutron's PTL duties are described very well in the All common
`PTL duties guide <https://docs.openstack.org/project-team-guide/ptl.html>`_.
Additionally to what is described in this guide, Neutron's PTL duties are:

- triage new RFEs and prepare `Neutron drivers team meeting
  <http://eavesdrop.openstack.org/#Neutron_drivers_Meeting>`_,

- maintain list of the :ref:`stadium projects<neutron_stadium>` health - if
  each project has gotten active team members and if it is following community
  and Neutron's guidelines and goals,

- maintain list of the :ref:`stadium projects
  lieutenants<subproject_lieutenants>` - check if those people are still active
  in the projects, if their contact data are correct, maybe there is someone
  new who is active in the stadium project and could be added to this list.

Over the past few years, the Neutron team has followed a mentoring
approach for:

- new contributors,
- potential new core reviewers,
- future PTLs.

The Neutron PTL's responsibility is to identify potential new core reviewers
and help with their mentoring process.
Mentoring of new contributors and potential core reviewers can be of course
delegated to the other members of the Neutron team.
Mentoring of future PTLs is responibility of the Neutron PTL.
