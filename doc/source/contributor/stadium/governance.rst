..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.


      Convention for heading levels in Neutron devref:
      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4
      (Avoid deeper levels because they do not render well.)


Stadium Governance
==================

Background
----------

Neutron grew to become a big monolithic codebase, and its core team had a
tough time making progress on a number of fronts, like adding new
features, ensuring stability, etc. During the Kilo timeframe, a
decomposition effort started, where the codebase got disaggregated into
separate repos, like the `high level services <http://specs.openstack.org/openstack/neutron-specs/specs/kilo/services-split.html>`_,
and the various third-party solutions for `L2 and L3 services <http://specs.openstack.org/openstack/neutron-specs/specs/kilo/core-vendor-decomposition.html>`_,
and the Stadium was officially born.

These initiatives enabled the various individual teams in charge of the
smaller projects the opportunity to iterate faster and reduce the time to
feature. This has been due to the increased autonomy and implicit trust model
that made the lack of oversight of the PTL and the Neutron drivers/core team
acceptable for a small number of initiatives. When the proposed `arrangement <https://review.openstack.org/#/c/175952/>`_
allowed projects to be `automatically <http://git.openstack.org/cgit/openstack/governance/commit/?id=321a020cbcaada01976478ea9f677ebb4df7bd6d>`_
enlisted as a Neutron project based simply on description, and desire for
affiliation, the number of projects included in the Stadium started to grow
rapidly, which created a number of challenges for the PTL and the drivers
team.

In fact, it became harder and harder to ensure consistency in the APIs,
architecture, design, implementation and testing of the overarching project;
all aspects of software development, like documentation, integration, release
management, maintenance, and upgrades started to being neglected for some
projects and that led to some unhappy experiences.

The point about uniform APIs is particularly important, because the Neutron
platform is so flexible that a project can take a totally different turn in
the way it exposes functionality, that it is virtually impossible for the
PTL and the drivers team to ensure that good API design principles are being
followed over time. In a situation where each project is on its own, that
might be acceptable, but allowing independent API evolution while still under
the Neutron umbrella is counterproductive.

These challenges led the Neutron team to find a better balance between autonomy
and consistency and lay down criteria that more clearly identify when a project
can be eligible for inclusion in the `Neutron governance <http://governance.openstack.org/reference/projects/neutron.html>`_.

This document describes these criteria, and document the steps involved to
maintain the integrity of the Stadium, and how to ensure this integrity be
maintained over time when modifications to the governance are required.

When is a project considered part of the Stadium?
-------------------------------------------------

In order to be considered part of the Stadium, a project must show a track
record of alignment with the Neutron `core project <http://git.openstack.org/cgit/openstack/neutron>`_.
This means showing proof of adoption of practices as led by the Neutron core
team. Some of these practices are typically already followed by the most
mature OpenStack projects:

* Exhaustive documentation: it is expected that each project will have a
  :doc:`developer </contributor/index>`,
  :doc:`user/operator </admin/index>`
  and `API <http://developer.openstack.org/api-ref/networking/>`_
  documentations available.

* Exhaustive OpenStack CI coverage: unit, functional, and tempest coverage
  using OpenStack CI (upstream) resources so that `Grafana <http://grafana.openstack.org/dashboard/db/neutron-failure-rate>`_
  and `OpenStack Health <http://status.openstack.org/openstack-health/#/>`_
  support is available. Access to CI resources and historical data by the
  team is key to ensuring stability and robustness of a project.
  In particular, it is of paramount importance to ensure that DB models/migrations
  are tested functionally to prevent data inconsistency issues or unexpected
  DB logic errors due to schema/models mismatch. For more details, please
  look at the following resources:

  * https://review.openstack.org/#/c/346091/
  * https://review.openstack.org/#/c/346272/
  * https://review.openstack.org/#/c/346083/

  More Database related information can be found on:

  * :doc:`/contributor/alembic_migrations`
  * :doc:`/contributor/internals/db_layer`

  Bear in mind that many projects have been transitioning their codebase and
  tests to fully support Python 3+, and it is important that each Stadium
  project supports Python 3+ the same way Neutron core does. For more
  information on how to do testing, please refer to the
  :doc:`Neutron testing documentation </contributor/testing/testing>`.

* Good release footprint, according to the chosen `release model <http://governance.openstack.org/reference/tags/#release-management-tags>`_.

* Adherence to deprecation and `stable backports policies <http://governance.openstack.org/reference/tags/#stable-maintenance-tags>`_.

* Demonstrated ability to do `upgrades <http://governance.openstack.org/reference/tags/assert_supports-upgrade.html>`_
  and/or `rolling upgrades <http://governance.openstack.org/reference/tags/assert_supports-rolling-upgrade.html>`_,
  where applicable. This means having grenade support on top of the CI
  coverage as described above.

* Client bindings and CLI developed according to the OpenStack Client `plugin model <https://docs.openstack.org/python-openstackclient/latest/plugins.html>`_.

On top of the above mentioned criteria, the following also are taken into
consideration:

* A project must use, adopt and implement open software and technologies.

* A project must integrate with Neutron via one of the supported, advertised
  and maintained public Python APIs. REST API does not qualify (the project
  python-neutronclient is an exception).

* It adopts neutron-lib (with related hacking rules applied), and has proof
  of good decoupling from Neutron core internals.

* It provides an API that adopts API guidelines as set by the Neutron core
  team, and that relies on an open implementation.

* It adopts modular interfaces to provide networking services: this means
  that L2/7 services are provided in the form of ML2 mech drivers and
  service plugins respectively. A service plugin can expose a driver
  interface to support multiple backend technologies, and/or adopt the
  flavor framework as necessary.

.. _add-remove-projects-to-stadium:

Adding or removing projects to the Stadium
------------------------------------------

When a project is to be considered part of the Stadium, proof of compliance to
the aforementioned practices will have to be demonstrated typically for at
least two OpenStack releases. Application for inclusion is to be considered
only within the first milestone of each OpenStack cycle, which is the time when
the PTL and Neutron team do release planning, and have the most time available
to discuss governance issues.

Projects part of the Neutron Stadium have typically the first milestone to get
their house in order, during which time reassessment happens; if removed, because
of substantial lack of meeting the criteria, a project cannot reapply within
the same release cycle it has been evicted.

The process for proposing a repo into openstack/ and under the Neutron
governance is to propose a patch to the openstack/governance repository.
For example, to propose networking-foo, one would add the following entry
under Neutron in reference/projects.yaml::

    - repo: openstack/networking-foo
      tags:
        - name: release:independent

Typically this is a patch that the PTL, in collaboration with the project's
point of contact, will shepherd through the review process. This step is
undertaken once it is clear that all criteria are met. The next section
provides an informal checklist that shows what steps a project needs to
go through in order to enable the PTL and the TC to vote positively on
the proposed inclusion.

Once a project is included, it abides by the Neutron
:doc:`RFE submission process </contributor/policies/blueprints>`,
where specifications to neutron-specs are required for major API as well
as major architectural changes that may require core Neutron platform
enhancements.

Checklist
---------

* How to integrate documentation into docs.o.o: The documentation
  website has a section for `project developer documentation <https://docs.openstack.org/openstack-projects.html>`_.
  Each project in the Neutron Stadium must have an entry under the
  'Networking Sub Projects' section that points to the developer
  documentation for the project, available at ``https://docs.openstack.org/<your-project>/latest/``.
  This is a two step process that involves the following:

  * Build the artefacts: this can be done by following example
    https://review.openstack.org/#/c/293399/.
  * Publish the artefacts: this can be done by following example
    https://review.openstack.org/#/c/216448/.

  More information can also be found on the
  `project creator guide <http://docs.openstack.org/infra/manual/creators.html#add-link-to-your-developer-documentation>`_.

* How to integrate into Grafana: Grafana is a great tool that provides
  the ability to display historical series, like failure rates of
  OpenStack CI jobs. A few examples that added dashboards over time are:

  * `Neutron <https://review.openstack.org/#/c/278832/>`_.
  * `Networking-OVN <https://review.openstack.org/#/c/335791>`_.
  * `Networking-Midonet <https://review.openstack.org/#/c/315033>`_.

  Any subproject must have a Grafana dashboard that shows failure
  rates for at least Gate and Check queues.

* How to integrate into neutron-lib's CI: there are a number of steps
  required to integrate with neutron-lib CI and adopt neutron-lib in
  general. One step is to validate that neutron-lib master is working
  with the master of a given project that uses neutron-lib. For example
  `patch <https://review.openstack.org/#/c/338603/>`_ introduced such
  support for the Neutron project. Any subproject that wants to do the
  same would need to adopt the following few lines:

  #. https://review.openstack.org/#/c/338603/4/jenkins/jobs/projects.yaml@4685
  #. https://review.openstack.org/#/c/338603/3/zuul/layout.yaml@8501
  #. https://review.openstack.org/#/c/338603/4/grafana/neutron.yaml@39

  Line 1 and 2 respectively add a job to the periodic queue for the
  project, whereas line 3 introduced the failure rate trend for the
  periodic job to spot failure spikes etc. Make sure your project has
  the following:

  #. https://review.openstack.org/#/c/357086/
  #. https://review.openstack.org/#/c/359143/

* How to port api-ref over to neutron-lib: to publish the subproject
  API reference into the `Networking API guide <http://developer.openstack.org/api-ref/networking/>`_
  you must contribute the API documentation into neutron-lib's api-ref
  directory as done in the `WADL/REST transition patch <https://review.openstack.org/#/c/327510/>`_.
  Once this is done successfully, a link to the subproject API will
  show under the published `table of content <https://github.com/openstack/neutron-lib/blob/master/api-ref/source/index.rst>`_.
  An RFE bug tracking this effort effectively initiates the request
  for Stadium inclusion, where all the aspects as outlined in this
  documented are reviewed by the PTL.

* How to port API definitions over the neutron-lib: the most basic
  steps to port API definitions over to neutron-lib are demonstrated
  in the following patches:

  * https://review.openstack.org/#/c/353131/
  * https://review.openstack.org/#/c/353132/

  The `neutron-lib patch <https://review.openstack.org/#/c/353131/>`_
  introduces the elements that define the API, and testing coverage
  validates that the resource and actions maps use valid keywords.
  API reference documentation is provided alongside the definition to
  keep everything in one place.
  The `neutron patch <https://review.openstack.org/#/c/353132/>`_
  uses the Neutron extension framework to plug the API definition
  on top of the Neutron API backbone. The change can only merge when
  there is a released version of neutron-lib.

* How to integrate into the openstack release: every project in the
  Stadium must have release notes. In order to set up release notes,
  please see the patches below for an example on how to set up reno:

  * https://review.openstack.org/#/c/320904/
  * https://review.openstack.org/#/c/243085/

  For release documentation related to Neutron, please check the
  :doc:`/contributor/policies/index`.
  Once, everything is set up and your project is released, make sure
  you see an entry on the release page (e.g. `Pike <http://releases.openstack.org/pike/index.html#other-projects>`_.
  Make sure you release according to the project declared release
  `model <http://governance.openstack.org/reference/projects/neutron.html#deliverables-and-tags>`_.

* How to port OpenStack Client over to python-neutronclient: client
  API bindings and client command line interface support must be
  developed in python-neutronclient under `osc module <https://github.com/openstack/python-neutronclient/tree/master/neutronclient/osc/v2>`_.
  If your project requires one or both, consider looking at the
  following example on how to contribute these two python-neutronclient
  according to the OSC framework and guidelines:

  * https://review.openstack.org/#/c/340624/
  * https://review.openstack.org/#/c/340763/
  * https://review.openstack.org/#/c/352653/

  More information on how to develop python-openstackclient plugins
  can be found on the following links:

  * https://docs.openstack.org/python-openstackclient/latest/contributor/plugins.html
  * https://docs.openstack.org/python-openstackclient/latest/contributor/humaninterfaceguide.html

  It is worth prefixing the commands being added with the keyword
  `network <https://review.openstack.org/#/c/340624/10/setup.cfg>`_ to
  avoid potential clash with other commands with similar names. This
  is only required if the command object name is highly likely to have
  an ambiguous meaning.
