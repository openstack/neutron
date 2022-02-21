Recheck Failed CI jobs in Neutron
=================================

This document provides guidelines on what to do in case your patch fails one of
the Zuul CI jobs. In order to discover potential bugs hidden in the code or
tests themselves, it's very helpful to check failed scenarios to investigate
the cause of the failure. Sometimes the failure will be caused by the patch
being tested, while other times the failure can be caused by a previously
untracked bug. Such failures are usually related to tests that interact with
a live system, like functional, fullstack and tempest jobs.

Before issuing a recheck on your patch, make sure that the gate failure is not
caused by your patch. Failed job can be also caused by some infra issue, for
example unable to fetch things from external resources like git or pip due to
outage. Such failures outside of OpenStack world are not worth tracking in
launchpad and you can recheck leaving couple of words what went wrong. Data
about gate stability is collected and visualized via
`Grafana <https://grafana.opendev.org/d/f913631585/neutron-failure-rate>`_.

Please, do not recheck without providing the bug number for the failed job.
For example, do not just put an empty "recheck" comment but find the related
bug number and put a "recheck bug ######" comment instead. If a bug does not
exist yet, create one so other team members can have a look. It helps us
maintain better visibility of gate failures. You can find how to troubleshoot
gate failures in the :ref:`Gate Failure Triage <troubleshooting-tempest-jobs>`
documentation.
