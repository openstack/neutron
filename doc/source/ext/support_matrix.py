# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
"""
This provides a sphinx extension able to render the
source/general_feature_support_matrix.ini
file into the developer documentation.

It is used via a single directive in the .rst file

  .. support_matrix::

"""

import re

from docutils import nodes
from docutils.parsers import rst
from six.moves import configparser

RE_PATTERN = re.compile("[^a-zA-Z0-9_]")


class SupportMatrix(object):
    """Represents the entire support matrix for Neutron drivers"""

    def __init__(self):
        self.features = []
        self.targets = {}


class SupportMatrixFeature(object):
    STATUS_IMMATURE = "immature"
    STATUS_MATURE = "mature"
    STATUS_REQUIRED = "required"
    STATUS_DEPRECATED = "deprecated"

    STATUS_ALL = [STATUS_IMMATURE, STATUS_MATURE,
                  STATUS_REQUIRED, STATUS_DEPRECATED]

    def __init__(self, key, title, status=STATUS_IMMATURE,
                 group=None, notes=None, cli=(), api=None):
        self.key = key
        self.title = title
        self.status = status
        self.group = group
        self.notes = notes
        self.cli = cli
        self.api = api

        self.implementations = {}


class SupportMatrixImplementation(object):
    STATUS_COMPLETE = "complete"
    STATUS_PARTIAL = "partial"
    STATUS_INCOMPLETE = "incomplete"
    STATUS_UNKNOWN = "unknown"

    STATUS_ALL = [STATUS_COMPLETE, STATUS_INCOMPLETE,
                  STATUS_PARTIAL, STATUS_UNKNOWN]

    def __init__(self, status=STATUS_INCOMPLETE, notes=None):

        self.status = status
        self.notes = notes


STATUS_DICT = {
    SupportMatrixImplementation.STATUS_COMPLETE: u"\u2714",
    SupportMatrixImplementation.STATUS_INCOMPLETE: u"\u2716",
    SupportMatrixImplementation.STATUS_PARTIAL: u"\u2714",
    SupportMatrixImplementation.STATUS_UNKNOWN: u"?"
}


class SupportMatrixTarget(object):
    def __init__(self, key, title, driver, plugin=None,
                 architecture=None, api=None, link=None):
        """:param key: Unique identifier for plugin
        :param title: Human readable name for plugin
        :param driver: name of the driver
        :param plugin: optional name of plugin
        :param architecture: optional name of architecture
        """
        self.api = api
        self.key = key
        self.title = title
        self.driver = driver
        self.plugin = plugin
        self.architecture = architecture
        self.link = link


class SupportMatrixDirective(rst.Directive):

    # general_feature_support_matrix.ini is the arg
    required_arguments = 1

    def run(self):
        matrix = self._load_support_matrix()
        return self._build_markup(matrix)

    def _load_support_matrix(self):
        """Reads the support-matrix.ini file and populates an instance
        of the SupportMatrix class with all the data.

        :returns: SupportMatrix instance
        """

        cfg = configparser.SafeConfigParser()
        env = self.state.document.settings.env
        fname = self.arguments[0]
        rel_fpath, fpath = env.relfn2path(fname)
        with open(fpath) as fp:
            cfg.readfp(fp)

        # This ensures that the docs are rebuilt whenever the
        # .ini file changes
        env.note_dependency(rel_fpath)

        matrix = SupportMatrix()
        matrix.targets = self._get_targets(cfg)
        matrix.features = self._get_features(cfg, matrix.targets)

        return matrix

    def _get_targets(self, cfg):
        # The 'target.<foo>' sections are special - they list all the
        # backend drivers that this file records data for

        targets = {}

        for section in cfg.sections():
            if not section.startswith("target."):
                continue

            key = cfg.get(section, "label")
            name = key.split("-")
            title = cfg.get(section, "title")
            link = cfg.get(section, "link")
            target = SupportMatrixTarget(key, title, *name, link=link)
            targets[key] = target

        return targets

    def _get_features(self, cfg, targets):
        # All sections except 'targets' describe some feature of
        # the Neutron backend driver.

        features = []

        for section in cfg.sections():
            if section.startswith("target."):
                continue
            if not cfg.has_option(section, "title"):
                raise Exception(
                    "'title' field missing in '[%s]' section" % section)

            title = cfg.get(section, "title")

            status = SupportMatrixFeature.STATUS_IMMATURE
            if cfg.has_option(section, "status"):
                # The value is a string "status(group)" where
                # the 'group' part is optional
                status = cfg.get(section, "status")
                offset = status.find("(")
                group = None
                if offset != -1:
                    group = status[offset + 1:-1]
                    status = status[0:offset]

                if status not in SupportMatrixFeature.STATUS_ALL:
                    raise Exception(
                        "'status' field value '%s' in ['%s']"
                        "section must be %s" %
                        (status, section,
                         ",".join(SupportMatrixFeature.STATUS_ALL)))

            cli = []
            if cfg.has_option(section, "cli"):
                cli = cfg.get(section, "cli")

            api = None
            if cfg.has_option(section, "api"):
                api = cfg.get(section, "api")

            notes = None
            if cfg.has_option(section, "notes"):
                notes = cfg.get(section, "notes")
            feature = SupportMatrixFeature(section, title, status, group,
                                           notes, cli, api)

            # Now we've got the basic feature details, we must process
            # the backend driver implementation for each feature
            for item in cfg.options(section):
                network_notes = "networking-notes-"

                if not item.startswith("networking-"):
                    continue

                if item not in targets:
                    raise Exception(
                        "networking-'%s' in '[%s]' not declared" %
                        (item, section))

                status = cfg.get(section, item)
                if status not in SupportMatrixImplementation.STATUS_ALL:
                    raise Exception(
                        "'%s' value '%s' in '[%s]' section must be %s" %
                        (item, status, section,
                         ",".join(SupportMatrixImplementation.STATUS_ALL)))
                notes_key = network_notes + item[len(network_notes):]
                notes = None
                if cfg.has_option(section, notes_key):
                    notes = cfg.get(section, notes_key)

                target = targets[item]
                impl = SupportMatrixImplementation(status, notes)
                feature.implementations[target.key] = impl

            for key in targets:
                if key not in feature.implementations:
                    raise Exception("'%s' missing in '[%s]' section" %
                                    (target.key, section))

            features.append(feature)

        return features

    def _build_markup(self, matrix):
        """Constructs the docutils content for the support matrix
        """
        content = []
        self._build_summary(matrix, content)
        self._build_details(matrix, content)
        self._build_notes(content)
        return content

    def _build_summary(self, matrix, content):
        """Constructs the docutils content for the summary of
        the support matrix.

        The summary consists of a giant table, with one row
        for each feature, and a column for each backend
        driver. It provides an 'at a glance' summary of the
        status of each driver
        """

        summary_title = nodes.subtitle(text="Summary")
        summary = nodes.table()
        cols = len(matrix.targets.keys())
        cols += 2
        summary_group = nodes.tgroup(cols=cols)
        summary_body = nodes.tbody()
        summary_head = nodes.thead()

        for i in range(cols):
            summary_group.append(nodes.colspec(colwidth=1))
        summary_group.append(summary_head)
        summary_group.append(summary_body)
        summary.append(summary_group)
        content.append(summary_title)
        content.append(summary)

        # This sets up all the column headers - two fixed
        # columns for feature name & status
        header = nodes.row()
        blank = nodes.entry()
        blank.append(nodes.emphasis(text="Feature"))
        header.append(blank)
        blank = nodes.entry()
        blank.append(nodes.emphasis(text="Status"))
        header.append(blank)
        summary_head.append(header)

        # then one column for each backend driver
        impls = matrix.targets.keys()
        impls = sorted(impls)
        for key in impls:
            target = matrix.targets[key]
            implcol = nodes.entry()
            header.append(implcol)
            if target.link:
                uri = target.link
                target_ref = nodes.reference("", refuri=uri)
                target_txt = nodes.inline()
                implcol.append(target_txt)
                target_txt.append(target_ref)
                target_ref.append(nodes.strong(text=target.title))
            else:
                implcol.append(nodes.strong(text=target.title))

        # We now produce the body of the table, one row for
        # each feature to report on
        for feature in matrix.features:
            item = nodes.row()

            # the hyperlink target name linking to details
            feature_id = re.sub(RE_PATTERN, "_", feature.key)

            # first the fixed columns for title/status
            key_col = nodes.entry()
            item.append(key_col)
            key_ref = nodes.reference(refid=feature_id)
            key_txt = nodes.inline()
            key_col.append(key_txt)
            key_txt.append(key_ref)
            key_ref.append(nodes.strong(text=feature.title))

            status_col = nodes.entry()
            item.append(status_col)
            status_col.append(nodes.inline(
                text=feature.status,
                classes=["sp_feature_" + feature.status]))

            # and then one column for each backend driver
            impls = matrix.targets.keys()
            impls = sorted(impls)
            for key in impls:
                target = matrix.targets[key]
                impl = feature.implementations[key]
                impl_col = nodes.entry()
                item.append(impl_col)

                key_id = re.sub(RE_PATTERN, "_",
                                "{}_{}".format(feature.key, key))

                impl_ref = nodes.reference(refid=key_id)
                impl_txt = nodes.inline()
                impl_col.append(impl_txt)
                impl_txt.append(impl_ref)

                status = STATUS_DICT.get(impl.status, "")

                impl_ref.append(nodes.literal(
                    text=status,
                    classes=["sp_impl_summary", "sp_impl_" + impl.status]))

            summary_body.append(item)

    def _build_details(self, matrix, content):
        """Constructs the docutils content for the details of
        the support matrix.
        """

        details_title = nodes.subtitle(text="Details")
        details = nodes.bullet_list()

        content.append(details_title)
        content.append(details)

        # One list entry for each feature we're reporting on
        for feature in matrix.features:
            item = nodes.list_item()

            status = feature.status
            if feature.group is not None:
                status += "({})".format(feature.group)

            feature_id = re.sub(RE_PATTERN, "_", feature.key)

            # Highlight the feature title name
            item.append(nodes.strong(text=feature.title, ids=[feature_id]))

            # Add maturity status
            para = nodes.paragraph()
            para.append(nodes.strong(text="Status: {} ".format(status)))
            item.append(para)

            # If API Alias exists add it
            if feature.api is not None:
                para = nodes.paragraph()
                para.append(
                    nodes.strong(text="API Alias: {} ".format(feature.api)))
                item.append(para)

            if feature.cli:
                item.append(self._create_cli_paragraph(feature))

            if feature.notes is not None:
                item.append(self._create_notes_paragraph(feature.notes))

            para_divers = nodes.paragraph()
            para_divers.append(nodes.strong(text="Driver Support:"))
            # A sub-list giving details of each backend driver target
            impls = nodes.bullet_list()
            for key in feature.implementations:
                target = matrix.targets[key]
                impl = feature.implementations[key]
                subitem = nodes.list_item()

                key_id = re.sub(RE_PATTERN, "_",
                                "{}_{}".format(feature.key, key))

                subitem += [
                    nodes.strong(text="{}: ".format(target.title)),
                    nodes.literal(text=impl.status,
                                  classes=["sp_impl_{}".format(impl.status)],
                                  ids=[key_id]),
                ]
                if impl.notes is not None:
                    subitem.append(self._create_notes_paragraph(impl.notes))
                impls.append(subitem)

            para_divers.append(impls)
            item.append(para_divers)
            details.append(item)

    def _build_notes(self, content):
        """Constructs a list of notes content for the support matrix.

        This is generated as a bullet list.
        """
        notes_title = nodes.subtitle(text="Notes:")
        notes = nodes.bullet_list()

        content.append(notes_title)
        content.append(notes)

        for note in ["This document is a continuous work in progress"]:
            item = nodes.list_item()
            item.append(nodes.strong(text=note))
            notes.append(item)

    def _create_cli_paragraph(self, feature):
        """Create a paragraph which represents the CLI commands of the feature

        The paragraph will have a bullet list of CLI commands.
        """
        para = nodes.paragraph()
        para.append(nodes.strong(text="CLI commands:"))
        commands = nodes.bullet_list()
        for c in feature.cli.split(";"):
            cli_command = nodes.list_item()
            cli_command += nodes.literal(text=c, classes=["sp_cli"])
            commands.append(cli_command)
        para.append(commands)
        return para

    def _create_notes_paragraph(self, notes):
        """Constructs a paragraph which represents the implementation notes

        The paragraph consists of text and clickable URL nodes if links were
        given in the notes.
        """
        para = nodes.paragraph()
        para.append(nodes.strong(text="Notes: "))
        # links could start with http:// or https://
        link_idxs = [m.start() for m in re.finditer('https?://', notes)]
        start_idx = 0
        for link_idx in link_idxs:
            # assume the notes start with text (could be empty)
            para.append(nodes.inline(text=notes[start_idx:link_idx]))
            # create a URL node until the next text or the end of the notes
            link_end_idx = notes.find(" ", link_idx)
            if link_end_idx == -1:
                # In case the notes end with a link without a blank
                link_end_idx = len(notes)
            uri = notes[link_idx:link_end_idx + 1]
            para.append(nodes.reference("", uri, refuri=uri))
            start_idx = link_end_idx + 1

        # get all text after the last link (could be empty) or all of the
        # text if no link was given
        para.append(nodes.inline(text=notes[start_idx:]))
        return para


def setup(app):
    app.add_directive('support_matrix', SupportMatrixDirective)
    app.add_stylesheet('support_matrix.css')
