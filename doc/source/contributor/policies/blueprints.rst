Blueprints and Specs
====================

The Neutron team uses the `neutron-specs
<http://opendev.org/openstack/neutron-specs>`_ repository for its
specification reviews. Detailed information can be found on the `wiki
<https://wiki.openstack.org/wiki/Blueprints>`_. Please also find
additional information in the reviews.rst file.

The Neutron team does not enforce deadlines for specs. These can be submitted
throughout the release cycle. The drivers team will review this on a regular
basis throughout the release, and based on the load for the milestones, will
assign these into milestones or move them to the backlog for selection into
a future release.

Please note that we use a `template
<http://opendev.org/openstack/neutron-specs/tree/specs/template.rst>`_
for spec submissions. It is not required to fill out all sections in the
template. Review of the spec may require filling in information left out by
the submitter.

Sub-Projects and Specs
----------------------

The `neutron-specs <http://opendev.org/openstack/neutron-specs>`_
repository is only meant for specs from Neutron itself, and the advanced
services repositories as well. This includes FWaaS and VPNaaS. Other
sub-projects are encouraged to fold their specs into their own devref code
in their sub-project gerrit repositories. Please see additional comments
in the Neutron teams :ref:`section <specs-core-reviewer-team>`
for reviewer requirements of the neutron-specs repository.

.. _request-for-feature-enhancement:

Neutron Request for Feature Enhancements
----------------------------------------

In Liberty the team introduced the concept of feature requests. Feature
requests are tracked as Launchpad bugs, by tagging them with a set of tags
starting with `rfe`, enabling the submission and review of feature requests
before code is submitted.
This allows the team to verify the validity of a feature request before the
process of submitting a neutron-spec is undertaken, or code is written.  It
also allows the community to express interest in a feature by subscribing to
the bug and posting a comment in Launchpad. The 'rfe' tag should not be used
for work that is already well-defined and has an assignee. If you are intending
to submit code immediately, a simple bug report will suffice. Note the
temptation to game the system exists, but given the history in Neutron for this
type of activity, it will not be tolerated and will be called out as such in
public on the mailing list.

RFEs can be submitted by anyone and by having the community vote on them in
Launchpad, we can gauge interest in features. The drivers team will evaluate
these on a weekly basis along with the specs. RFEs will be evaluated in the
current cycle against existing project priorities and available resources.

The workflow for the life an RFE in Launchpad is as follows:

* The bug is submitted and will by default land in the "New" state.
  Anyone can make a bug an RFE by adding the `rfe` tag.
* As soon as a member of the neutron-drivers team acknowledges the bug,
  the `rfe` tag will be replaced with the `rfe-confirmed` tag. No assignee, or
  milestone is set at this time. The importance will be set to 'Wishlist' to
  signal the fact that the report is indeed a feature or enhancement and there
  is no severity associated to it.
* A member of the neutron-drivers team replaces the `rfe-confirmed` tag with
  the `rfe-triaged` tag when he/she thinks it's ready to be discussed in the
  drivers meeting.  The bug will be in this state while the discussion is
  ongoing.
* The neutron-drivers team will evaluate the RFE and may advise the submitter
  to file a spec in neutron-specs to elaborate on the feature request, in case
  the RFE requires extra scrutiny, more design discussion, etc.
* The PTL will work with the Lieutenant for the area being identified by the
  RFE to evaluate resources against the current workload.
* A member of the Neutron release team (or the PTL) will register a matching
  Launchpad blueprint to be used for milestone tracking purposes, and for
  identifying the responsible assignee and approver. If the RFE has a spec
  the blueprint will have a pointer to the spec document, which will become
  available on `specs.o.o. <http://specs.openstack.org/openstack/neutron-specs/>`_
  once it is approved and merged. The blueprint will then be linked to the
  original RFE bug report as a pointer to the discussion that led to the
  approval of the RFE.
  The blueprint submitter will also need to identify the following:

  * Priority: there will be only two priorities to choose from, High and Low.
    It is worth noting that priority is not to be confused with
    `importance <https://docs.openstack.org/project-team-guide/bugs.html#Importance>`_,
    which is a property of Launchpad Bugs. Priority gives an indication of
    how promptly a work item should be tackled to allow it to complete. High
    priority is to be chosen for work items that must make substantial
    progress in the span of the targeted release, and deal with the
    following aspects:

    * OpenStack cross-project interaction and interoperability issues;
    * Issues that affect the existing system's usability;
    * Stability and testability of the platform;
    * Risky implementations that may require complex and/or pervasive
      changes to API and the logical model;

    Low priority is to be chosen for everything else. RFEs without an associated
    blueprint are effectively equivalent to low priority items. Bear in mind that,
    even though staffing should take priorities into account (i.e. by giving more
    resources to high priority items over low priority ones), the open source
    reality is that they can both proceed at their own pace and low priority items
    can indeed complete faster than high priority ones, even though they are
    given fewer resources.

  * Drafter: who is going to submit and iterate on the spec proposal; he/she
    may be the RFE submitter.
  * Assignee: who is going to develop the bulk of the code, or the
    go-to contributor, if more people are involved. Typically this is
    the RFE submitter, but not necessarily.
  * Approver: a member of the Neutron team who can commit enough time
    during the ongoing release cycle to ensure that code posted for review
    does not languish, and that all aspects of the feature development are
    taken care of (client, server changes and/or support from other projects
    if needed - tempest, nova, openstack-infra, devstack, etc.), as well as
    comprehensive testing.
    This is typically a core member who has enough experience with what it
    takes to get code merged, but other resources amongst the wider team can
    also be identified. Approvers are volunteers who show a specific interest
    in the blueprint specification, and have enough insight in the area of
    work so that they can make effective code reviews and provide design
    feedback. An approver will not work in isolation, as he/she can and will
    reach out for help to get the job done; however he/she is the main
    point of contact with the following responsibilities:

    * Pair up with the drafter/assignee in order to help skip development
      blockers.
    * Review patches associated with the blueprint: approver and assignee
      should touch base regularly and ping each other when new code is
      available for review, or if review feedback goes unaddressed.
    * Reach out to other reviewers for feedback in areas that may step
      out of the zone of her/his confidence.
    * Escalate issues, and raise warnings to the release team/PTL if the
      effort shows slow progress. Approver and assignee are key parts to land
      a blueprint: should the approver and/or assignee be unable to continue
      the commitment during the release cycle, it is the Approver's
      responsibility to reach out the release team/PTL so that replacements
      can be identified.
    * Provide a status update during the Neutron IRC meeting, if required.

    Approver `assignments <https://blueprints.launchpad.net/neutron/+assignments>`_
    must be carefully identified to ensure that no-one overcommits. A
    Neutron contributor develops code himself/herself, and if he/she is an
    approver of more than a couple of blueprints in a single cycle/milestone
    (depending on the complexity of the spec), it may mean that he/she is
    clearly oversubscribed.

  The Neutron team will review the status of blueprints targeted for the
  milestone during their weekly meeting to ensure a smooth progression of
  the work planned. Blueprints for which resources cannot be identified
  will have to be deferred.

* In either case (a spec being required or not), once the discussion has
  happened and there is positive consensus on the RFE, the report is 'approved',
  and its tag will move from `rfe-triaged` to `rfe-approved`.
* An RFE can be occasionaly marked as 'rfe-postponed' if the team identifies
  a dependency between the proposed RFE and other pending tasks that prevent
  the RFE from being worked on immediately.
* Once an RFE is approved, it needs volunteers. Approved RFEs that do not have an
  assignee but sound relatively simple or limited in scope (e.g. the addition of
  a new API with no ramification in the plugin backends), should be promoted
  during team meetings or the ML so that volunteers can pick them up and get
  started with neutron development. The team will regularly scan `rfe-approved`
  or `rfe-postponed` RFEs to see what their latest status is and mark them
  incomplete if no assignees can be found, or they are no longer relevant.
* As for setting the milestone (both for RFE bugs or blueprints), the current
  milestone is always chosen, assuming that work will start as soon as the feature
  is approved. Work that fails to complete by the defined milestone will roll
  over automatically until it gets completed or abandoned.
* If the code fails to merge, the bug report may be marked as incomplete,
  unassigned and untargeted, and it will be garbage collected by
  the Launchpad Janitor if no-one takes over in time. Renewed interest in the
  feature will have to go through RFE submission process once again.

In summary:

+------------+-----------------------------------------------------------------------------+
|State       | Meaning                                                                     |
+============+=============================================================================+
|New         | This is where all RFE's start, as filed by the community.                   |
+------------+-----------------------------------------------------------------------------+
|Incomplete  | Drivers/LTs - Move to this state to mean, "more needed before proceeding"   |
+------------+-----------------------------------------------------------------------------+
|Confirmed   | Drivers/LTs - Move to this state to mean, "yeah, I see that you filed it"   |
+------------+-----------------------------------------------------------------------------+
|Triaged     | Drivers/LTs - Move to this state to mean, "discussion is ongoing"           |
+------------+-----------------------------------------------------------------------------+
|Won't Fix   | Drivers/LTs - Move to this state to reject an RFE.                          |
+------------+-----------------------------------------------------------------------------+

Once the triaging (discussion is complete) and the RFE is approved, the tag goes from 'rfe'
to 'rfe-approved', and at this point the bug report goes through the usual state transition.
Note, that the importance will be set to 'wishlist', to reflect the fact that the bug report
is indeed not a bug, but a new feature or enhancement. This will also help have RFEs that are
not followed up by a blueprint standout in the Launchpad `milestone dashboards <https://launchpad.net/neutron/+milestones>`_.

The drivers team will be discussing the following bug reports during their IRC meeting:

* `New RFE's <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=NEW&field.tag=rfe>`_
* `Incomplete RFE's <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INCOMPLETE&field.tag=rfe>`_
* `Confirmed RFE's <https://bugs.launchpad.net/neutron/+bugs?field.tag=rfe-confirmed>`_
* `Triaged RFE's <https://bugs.launchpad.net/neutron/+bugs?field.tag=rfe-triaged>`_


RFE Submission Guidelines
-------------------------

Before we dive into the guidelines for writing a good RFE, it is worth mentioning
that depending on your level of engagement with the Neutron project and your role
(user, developer, deployer, operator, etc.), you are more than welcome to have
a preliminary discussion of a potential RFE by reaching out to other people involved
in the project. This usually happens by posting mails on the relevant mailing
lists (e.g. `openstack-discuss <http://lists.openstack.org>`_ - include [neutron] in
the subject) or on #openstack-neutron IRC channel on Freenode. If current ongoing
code reviews are related to your feature, posting comments/questions on gerrit
may also be a way to engage. Some amount of interaction with Neutron developers
will give you an idea of the plausibility and form of your RFE before you submit
it. That said, this is not mandatory.

When you submit a bug report on https://bugs.launchpad.net/neutron/+filebug,
there are two fields that must be filled: 'summary' and 'further information'.
The 'summary' must be brief enough to fit in one line: if you can't describe it
in a few words it may mean that you are either trying to capture more than one
RFE at once, or that you are having a hard time defining what you are trying to
solve at all.

The 'further information' section must be a description of what you would like
to see implemented in Neutron. The description should provide enough details for
a knowledgeable developer to understand what is the existing problem in the
current platform that needs to be addressed, or what is the enhancement that
would make the platform more capable, both for a functional and a non-functional
standpoint. To this aim it is important to describe 'why' you believe the RFE
should be accepted, and motivate the reason why without it Neutron is a poorer
platform. The description should be self contained, and no external references
should be necessary to further explain the RFE.

In other words, when you write an RFE you should ask yourself the following
questions:

* What is that I (specify what user - a user can be a human or another system)
  cannot do today when interacting with Neutron? On the other hand, is there a
  Neutron component X that is unable to accomplish something?
* Is there something that you would like Neutron handle better, ie. in a more
  scalable, or in a more reliable way?
* What is that I would like to see happen after the RFE is accepted and
  implemented?
* Why do you think it is important?

Once you are happy with what you wrote, add 'rfe' as tag, and submit. Do not
worry, we are here to help you get it right! Happy hacking.


Missing your target
-------------------

There are occasions when a spec will be approved and the code will not land in
the cycle it was targeted at. For these cases, the work flow to get the spec
into the next release is as follows:

* During the RC window, the PTL will create a directory named '<release>' under
  the 'backlog' directory in the neutron specs repo, and he/she will move all
  specs that did not make the release to this directory.
* Anyone can propose a patch to neutron-specs which moves a spec from the
  previous release into the new release directory.

The specs which are moved in this way can be fast-tracked into the next
release. Please note that it is required to re-propose the spec for the new
release.


Documentation
-------------

The above process involves two places where any given feature can start to be
documented - namely in the RFE bug, and in the spec - and in addition to those
Neutron has a substantial :doc:`developer reference guide </contributor/index>`
(aka 'devref'), and user-facing docs such as
the :doc:`networking guide </admin/index>`. So it might be asked:

* What is the relationship between all of those?

* What is the point of devref documentation, if everything has already been
  described in the spec?

The answers have been beautifully expressed in an `openstack-dev post
<http://lists.openstack.org/pipermail/openstack-dev/2015-December/081458.html>`_:

1. RFE: "I want X"
2. Spec: "I plan to implement X like this"
3. devref: "How X is implemented and how to extend it"
4. OS docs: "API and guide for using X"

Once a feature X has been implemented, we shouldn't have to go to back to its
RFE bug or spec to find information on it.  The devref may reuse a lot of
content from the spec, but the spec is not maintained and the implementation
may differ in some ways from what was intended when the spec was agreed.  The
devref should be kept current with refactorings, etc., of the implementation.

Devref content should be added as part of the implementation of a new feature.
Since the spec is not maintained after the feature is implemented, the devref
should include a maintained version of the information from the spec.

If a feature requires OS docs (4), the feature patch shall include the new,
or updated, documentation changes.  If the feature is purely a developer
facing thing, (4) is not needed.
