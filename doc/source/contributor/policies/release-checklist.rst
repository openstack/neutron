Pre-release check list
======================

This page lists things to cover before a Neutron release and will serve as a
guide for next release managers.

Server
------

Major release
~~~~~~~~~~~~~

A Major release is cut off once per development cycle and has an assigned name
(Victoria, Wallaby, ...)

Prior to major release,

#. consider blocking all patches that are not targeted for the new release;
#. consider blocking trivial patches to keep the gate clean;
#. revise the current list of blueprints and bugs targeted for the release;
   roll over anything that does not fit there, or won't make it (note that no
   new features land in master after so called feature freeze is claimed by
   release team; there is a feature freeze exception (FFE) process described in
   release engineering documentation in more details:
   http://docs.openstack.org/project-team-guide/release-management.html );
#. start collecting state for targeted features from the team. For example,
   propose a post-mortem patch for neutron-specs as in:
   https://review.opendev.org/c/openstack/neutron-specs/+/286413/
#. revise deprecation warnings collected in latest Zuul runs: some of them
   may indicate a problem that should be fixed prior to release (see
   deprecations.txt file in those log directories); also, check whether any
   Launchpad bugs with the 'deprecation' tag need a clean-up or a follow-up in
   the context of the release being planned;
#. check that release notes and sample configuration files render correctly,
   arrange clean-up if needed;
#. ensure all doc links are valid by running ``tox -e linkcheck`` and
   addressing any broken links.

New major release process contains several phases:

#. master branch is blocked for patches that are not targeted for the release;
#. the whole team is expected to work on closing remaining pieces targeted for
   the release;
#. once the team is ready to release the first release candidate (RC1), either
   PTL or one of release liaisons proposes a patch for openstack/releases repo.
   For example, see: https://review.opendev.org/c/openstack/releases/+/753039/
#. once the openstack/releases patch lands, release team creates a new stable
   branch using hash values specified in the patch;
#. at this point, master branch is open for patches targeted to the next
   release; PTL unblocks all patches that were blocked in step 1;
#. if additional patches are identified that are critical for the release and
   must be shipped in the final major build, corresponding bugs are tagged
   with <release>-rc-potential in Launchpad, fixes are prepared and land in
   master branch, and are then backported to the newly created stable branch;
#. if patches landed in the release stable branch as per the previous step, a
   new release candidate that would include those patches should be requested
   by PTL in openstack/releases repo;
#. eventually, the latest release candidate requested by PTL becomes the final
   major release of the project.

Release candidate (RC) process allows for stabilization of the final release.

The following technical steps should be taken before the final release is cut
off:

#. the latest alembic script of the version that is being released is tagged
   with a milestone label; for example, in
   https://review.opendev.org/c/openstack/neutron/+/944804 the latest script
   is being tagged with ``RELEASE_2025_1``
#. the new release tag must be created; using the previous example, the tag
   ``RELEASE_2025_2`` is created.
#. add the released version tag to the ``NEUTRON_MILESTONES`` list; in the
   previous example, the tag ``RELEASE_2025_1`` is added to this list.
#. update the ``CURRENT_RELEASE`` variable with the new tag created and
   add it to the ``RELEASES`` tuple; in the previous example,
   ``RELEASE_2025_2`` is added to the ``RELEASES`` tuple and used as the
   current release milestone.

In the new stable branch, you should make sure that:

#. .gitreview file points to the new branch;
   https://review.opendev.org/c/openstack/neutron/+/754738/
#. if the branch uses constraints to manage gated dependency versions, the
   default constraints file name points to corresponding stable branch in
   openstack/requirements repo;
   https://review.opendev.org/c/openstack/neutron/+/754739/
#. job templates are updated to use versions for that branch;
   https://review.opendev.org/c/openstack/neutron-tempest-plugin/+/756585/ and
   https://review.opendev.org/c/openstack/neutron/+/759856/
#. all CI jobs running against master branch of another project are dropped;
   https://review.opendev.org/c/openstack/neutron/+/756695/
#. neutron itself is capped in requirements in the new branch;
   https://review.opendev.org/c/openstack/requirements/+/764022/
#. all new Neutron features without an API extension which have new tempest
   tests (in ``tempest`` or in ``neutron-tempest-plugin``) must have a new
   item in ``available_features`` list under ``network-feature-enabled``
   section in ``tempest.conf``.
   To make stable jobs execute only the necessary tests the list in devstack
   (devstack/lib/tempest) must be checked and filled;
   https://review.opendev.org/c/openstack/devstack/+/769885
#. Grafana dashboards for stable branches should be updated to point to the
   latest releases;
   https://review.opendev.org/c/openstack/project-config/+/757102
#. Check API extensions list in devstack:
   https://review.opendev.org/c/openstack/devstack/+/811485
   (Full list of QA related release checks can be found here:
   https://wiki.openstack.org/wiki/QA/releases#Projects_with_only_Branches

Note that some of those steps are covered by the OpenStack release team and its
release bot.

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

#. a patch for openstack/releases repo is proposed and merged.


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

#. when preparing for a major release, pay special attention to client bits
   that are targeted for the release. Global openstack/requirements freeze
   happens long before first RC release of server components. So if you plan to
   land server patches that depend on a new client, make sure you don't miss
   the requirements freeze. After the freeze is in action, there is no easy way
   to land more client patches for the planned target. All this may push an
   affected feature to the next development cycle.
