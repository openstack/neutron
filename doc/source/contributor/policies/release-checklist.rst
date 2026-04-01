Release checklist
=================

This page lists things to cover before, during, and after a Neutron release
and will serve as a guide for release managers.

Server
------

Major release
~~~~~~~~~~~~~

A Major release is cut off once per development cycle and has an assigned name
(Victoria, Wallaby, ...)

Prior to major release:

#. Consider blocking all patches that are not targeted for the new release
#. Consider blocking trivial patches to keep the gate clean
#. Revise the current list of blueprints and bugs targeted for the release;
   roll over anything that does not fit there, or won't make it (note that no
   new features land in master after so called feature freeze is claimed by
   release team; there is a feature freeze exception (FFE) process described in
   release engineering documentation in more details:
   https://docs.openstack.org/project-team-guide/release-management.html)
#. Start collecting state for targeted features from the team. For example,
   propose a post-mortem patch for neutron-specs as in:
   https://review.opendev.org/c/openstack/neutron-specs/+/286413/
#. Revise deprecation warnings collected in latest Zuul runs: some of them
   may indicate a problem that should be fixed prior to release (see
   deprecations.txt file in those log directories); also, check whether any
   Launchpad bugs with the 'deprecation' tag need a clean-up or a follow-up in
   the context of the release being planned
#. Update the OVS/OVN minimum requirement table in:
   ``doc/source/install/ovs-ovn-requirements.rst``
#. Check that release notes and sample configuration files render correctly,
   arrange clean-up if needed
#. Ensure all doc links are valid by running ``tox -e linkcheck`` and
   addressing any broken links

New major release process contains several phases:

#. Master branch is blocked for patches that are not targeted for the release
#. The whole team is expected to work on closing remaining pieces targeted for
   the release
#. Once the team is ready to release the first release candidate (RC1), either
   the PTL or one of release liaisons proposes a patch for openstack/releases
   repository. For example, see:
   https://review.opendev.org/c/openstack/releases/+/753039/
#. Once the openstack/releases patch lands, the release team creates a new
   stable branch using hash values specified in the patch
#. At this point, the master branch is open for patches targeted to the next
   release; PTL unblocks all patches that were blocked in step 1
#. If additional patches are identified that are critical for the release and
   must be shipped in the final major build, corresponding bugs are tagged
   with <release>-rc-potential in Launchpad, fixes are prepared and land in
   master branch, and are then backported to the newly created stable branch
#. If patches landed in the release stable branch as per the previous step, a
   new release candidate that would include those patches should be requested
   by the PTL in the openstack/releases repository
#. Eventually, the latest release candidate requested by PTL becomes the final
   major release of the project

Release candidate (RC) process allows for stabilization of the final release.

The following technical steps should be taken before the final release is cut
off:

#. The latest alembic script of the version that is being released is tagged
   with a milestone label; for example, in
   https://review.opendev.org/c/openstack/neutron/+/944804 the latest script
   is being tagged with ``RELEASE_2025_1``
#. The new release tag must be created; using the previous example, the tag
   ``RELEASE_2025_2`` is created
#. Add the released version tag to the ``NEUTRON_MILESTONES`` list; in the
   previous example, the tag ``RELEASE_2025_1`` is added to this list
#. Update the ``CURRENT_RELEASE`` variable with the new tag created and
   add it to the ``RELEASES`` tuple; in the previous example,
   ``RELEASE_2025_2`` is added to the ``RELEASES`` tuple and used as the
   current release milestone

In the new stable branch, you should make sure that:

#. .gitreview file points to the new branch
   https://review.opendev.org/c/openstack/neutron/+/754738/
#. If the branch uses constraints to manage gated dependency versions, the
   default constraints file name points to the corresponding stable branch in
   openstack/requirements repository
   https://review.opendev.org/c/openstack/neutron/+/754739/
#. Job templates are updated to use versions for that branch. First, add
   the stable neutron-tempest-plugin job definitions and template:
   https://review.opendev.org/c/openstack/neutron-tempest-plugin/+/980321/
   Then update the stable neutron and neutron-lib branches to use the new
   template, for example:
   https://review.opendev.org/c/openstack/neutron/+/981131/
   https://review.opendev.org/c/openstack/neutron-lib/+/981203
#. All CI jobs running against master branch of another project are dropped:
   https://review.opendev.org/c/openstack/neutron/+/756695/
#. Neutron itself is capped in requirements in the new branch:
   https://review.opendev.org/c/openstack/requirements/+/764022/
#. All new Neutron features without an API extension which have new tempest
   tests (in ``tempest`` or in ``neutron-tempest-plugin``) must have a new
   item in ``available_features`` list under ``network-feature-enabled``
   section in ``tempest.conf``.
   To make stable jobs execute only the necessary tests the list in devstack
   (devstack/lib/tempest) must be checked and filled:
   https://review.opendev.org/c/openstack/devstack/+/769885
#. Grafana dashboards for stable branches should be updated to point to the
   latest releases:
   https://review.opendev.org/c/openstack/project-config/+/757102
#. Check API extensions list in devstack:
   https://review.opendev.org/c/openstack/devstack/+/811485
   (Full list of QA related release checks can be found here:
   https://wiki.openstack.org/wiki/QA/releases#Projects_with_only_Branches

Note that some of those steps are covered by the OpenStack release team and its
release bot.

There are a set of tasks that must be performed for every release, shortly
after the previous releases stable branch is created:

#. For each release we alternate from testing skip-level upgrades (SLURP)
   in the check queue versus the experimental queue. For example, when
   the release ends in a .1 (e.g. 2026.1) we test upgrades from the previous
   .1 (e.g. 2025.1) release in the check queue. For releases ending in a .2
   these are only tested in the experimental and periodic queues.
   Changing from Non-SLURP to SLURP example patch:
   https://review.opendev.org/c/openstack/neutron/+/962240
   Changing from SLURP to Non-SLURP example patch:
   https://review.opendev.org/c/openstack/neutron/+/944808
#. Update versions of CI tools in ``tox.ini``, ``pyproject.toml`` and
   ``.pre-commit-config.yaml``. This should also be done occasionally during
   the cycle. An example patch:
   https://review.opendev.org/c/openstack/neutron/+/976562
#. Update and/or create job templates when new python versions are
   added in the governance repository. For example, when the governance is
   updated a new zuul template will be built, which could require a timeout
   override, or a small change to the jobs, for example:
   https://review.opendev.org/c/openstack/governance/+/957199
   https://review.opendev.org/c/openstack/openstack-zuul-jobs/+/958617
   https://review.opendev.org/c/openstack/neutron/+/977376
#. Update testing runtimes when necessary. When a new python version
   is added to be in the runtime, or when one is removed, a patch will
   be created for it. This could require a small change to the jobs:
   https://review.opendev.org/c/openstack/openstack-zuul-jobs/+/941246
   https://review.opendev.org/c/openstack/neutron/+/944809
#. Update other zuul templates as necessary. When a new python version is
   added, we need to create new job templates. For example, our jobs that
   run using the master branch of another library will need to be added:
   https://review.opendev.org/c/openstack/openstack-zuul-jobs/+/969911
#. Some of the above will need to be repeated for neutron-lib, as well
   as other neutron-* stadium projects - for example, updating CI tool
   versions and testing runtimes. Please see previous patches in the
   respective repositories for reference.

While preparing the next release and even in the middle of development, it's
worth keeping the infrastructure clean. Consider using these tools to declutter
the project infrastructure:

#. declutter Gerrit::

    <neutron>/tools/abandon_old_reviews.sh

#. declutter Launchpad::

    <release-tools>/pre_expire_bugs.py neutron --day <back-to-the-beginning-of-the-release>


Minor release
~~~~~~~~~~~~~

A Minor release is created from an existing stable branch after the initial
major release, and usually contains bug fixes and small improvements only.
The minor release frequency should follow the release schedule for the current
series. For example, assuming the current release is Rocky, stable branch
releases should coincide with milestones R1, R2, R3 and the final release.
Stable branches can be also released more frequently if needed, for example,
if there is a major bug fix that has merged recently.

The following steps should be taken before claiming a successful minor release:

#. a patch for openstack/releases repository is proposed and merged.


Minor version number should be bumped always in cases when new release contains
a patch which introduces for example:

#. new OVO version for an object,
#. new configuration option added,
#. requirement change,
#. API visible change,

The above list doesn't cover all possible cases. Those are only examples of
fixes which require bump of minor version number but there can be also other
types of changes requiring the same.

Changes that require the minor version number to be bumped should always have a
release note added.

In other cases only patch number can be bumped.


Client
------

Most tips from the Server section apply to client releases too. Several things
to note though:

#. When preparing for a major release, pay special attention to client bits
   that are targeted for the release. Global openstack/requirements freeze
   happens long before first RC release of server components. So if you plan to
   land server patches that depend on a new client, make sure you don't miss
   the requirements freeze. After the freeze is in action, there is no easy way
   to land more client patches for the planned target. All this may push an
   affected feature to the next development cycle.
