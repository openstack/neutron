# vim: tabstop=4 shiftwidth=4 softtabstop=4

#    Copyright 2012 OpenStack LLC
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Utilities for consuming the auto-generated versioninfo files.
"""

import datetime
import pkg_resources

import setup


class VersionInfo(object):

    def __init__(self, package, python_package=None, pre_version=None):
        """Object that understands versioning for a package
        :param package: name of the top level python namespace. For glance,
                        this would be "glance" for python-glanceclient, it
                        would be "glanceclient"
        :param python_package: optional name of the project name. For
                               glance this can be left unset. For
                               python-glanceclient, this would be
                               "python-glanceclient"
        :param pre_version: optional version that the project is working to
        """
        self.package = package
        if python_package is None:
            self.python_package = package
        else:
            self.python_package = python_package
        self.pre_version = pre_version
        self.version = None
        self._cached_version = None

    def _generate_version(self):
        """Defer to the openstack.common.setup routines for making a
        version from git."""
        if self.pre_version is None:
            return setup.get_post_version(self.package)
        else:
            return setup.get_pre_version(self.package, self.pre_version)

    def _newer_version(self, pending_version):
        """Check to see if we're working with a stale version or not.
        We expect a version string that either looks like:
          2012.2~f3~20120708.10.4426392
        which is an unreleased version of a pre-version, or:
          0.1.1.4.gcc9e28a
        which is an unreleased version of a post-version, or:
          0.1.1
        Which is a release and which should match tag.
        For now, if we have a date-embedded version, check to see if it's
        old, and if so re-generate. Otherwise, just deal with it.
        """
        try:
            version_date = int(self.version.split("~")[-1].split('.')[0])
            if version_date < int(datetime.date.today().strftime('%Y%m%d')):
                return self._generate_version()
            else:
                return pending_version
        except Exception:
            return pending_version

    def version_string_with_vcs(self, always=False):
        """Return the full version of the package including suffixes indicating
        VCS status.

        For instance, if we are working towards the 2012.2 release,
        canonical_version_string should return 2012.2 if this is a final
        release, or else something like 2012.2~f1~20120705.20 if it's not.

        :param always: if true, skip all version caching
        """
        if always:
            self.version = self._generate_version()

        if self.version is None:

            requirement = pkg_resources.Requirement.parse(self.python_package)
            versioninfo = "%s/versioninfo" % self.package
            try:
                raw_version = pkg_resources.resource_string(requirement,
                                                            versioninfo)
                self.version = self._newer_version(raw_version.strip())
            except (IOError, pkg_resources.DistributionNotFound):
                self.version = self._generate_version()

        return self.version

    def canonical_version_string(self, always=False):
        """Return the simple version of the package excluding any suffixes.

        For instance, if we are working towards the 2012.2 release,
        canonical_version_string should return 2012.2 in all cases.

        :param always: if true, skip all version caching
        """
        return self.version_string_with_vcs(always).split('~')[0]

    def version_string(self, always=False):
        """Return the base version of the package.

        For instance, if we are working towards the 2012.2 release,
        version_string should return 2012.2 if this is a final release, or
        2012.2-dev if it is not.

        :param always: if true, skip all version caching
        """
        version_parts = self.version_string_with_vcs(always).split('~')
        if len(version_parts) == 1:
            return version_parts[0]
        else:
            return '%s-dev' % (version_parts[0],)

    def cached_version_string(self, prefix=""):
        """Generate an object which will expand in a string context to
        the results of version_string(). We do this so that don't
        call into pkg_resources every time we start up a program when
        passing version information into the CONF constructor, but
        rather only do the calculation when and if a version is requested
        """
        if not self._cached_version:
            self._cached_version = "%s%s" % (prefix,
                                             self.version_string())
        return self._cached_version
