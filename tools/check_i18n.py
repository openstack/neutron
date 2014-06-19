#    Copyright 2012 OpenStack Foundation
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
from __future__ import print_function

import compiler
import imp
import os.path
import sys


def is_localized(node):
    """Check message wrapped by _()"""
    if isinstance(node.parent, compiler.ast.CallFunc):
        if isinstance(node.parent.node, compiler.ast.Name):
            if node.parent.node.name == '_':
                return True
    return False


class ASTWalker(compiler.visitor.ASTVisitor):

    def default(self, node, *args):
        for child in node.getChildNodes():
            child.parent = node
        compiler.visitor.ASTVisitor.default(self, node, *args)


class Visitor(object):

    def __init__(self, filename, i18n_msg_predicates,
                 msg_format_checkers, debug):
        self.filename = filename
        self.debug = debug
        self.error = 0
        self.i18n_msg_predicates = i18n_msg_predicates
        self.msg_format_checkers = msg_format_checkers
        with open(filename) as f:
            self.lines = f.readlines()

    def visitConst(self, node):
        if not isinstance(node.value, str):
            return

        if is_localized(node):
            for (checker, msg) in self.msg_format_checkers:
                if checker(node):
                    print('%s:%d %s: %s Error: %s' %
                          (self.filename, node.lineno,
                           self.lines[node.lineno - 1][:-1],
                           checker.__name__, msg),
                           file=sys.stderr)
                    self.error = 1
                    return
            if debug:
                print('%s:%d %s: %s' %
                      (self.filename, node.lineno,
                       self.lines[node.lineno - 1][:-1],
                       "Pass"))
        else:
            for (predicate, action, msg) in self.i18n_msg_predicates:
                if predicate(node):
                    if action == 'skip':
                        if debug:
                            print('%s:%d %s: %s' %
                                  (self.filename, node.lineno,
                                  self.lines[node.lineno - 1][:-1],
                                  "Pass"))
                        return
                    elif action == 'error':
                        print('%s:%d %s: %s Error: %s' %
                              (self.filename, node.lineno,
                               self.lines[node.lineno - 1][:-1],
                               predicate.__name__, msg),
                               file=sys.stderr)
                        self.error = 1
                        return
                    elif action == 'warn':
                        print('%s:%d %s: %s' %
                              (self.filename, node.lineno,
                              self.lines[node.lineno - 1][:-1],
                              "Warn: %s" % msg))
                        return
                    print('Predicate with wrong action!', file=sys.stderr)


def is_file_in_black_list(black_list, f):
    for f in black_list:
        if os.path.abspath(input_file).startswith(
            os.path.abspath(f)):
            return True
    return False


def check_i18n(input_file, i18n_msg_predicates, msg_format_checkers, debug):
    input_mod = compiler.parseFile(input_file)
    v = compiler.visitor.walk(input_mod,
                              Visitor(input_file,
                                      i18n_msg_predicates,
                                      msg_format_checkers,
                                      debug),
                              ASTWalker())
    return v.error


if __name__ == '__main__':
    input_path = sys.argv[1]
    cfg_path = sys.argv[2]
    try:
        cfg_mod = imp.load_source('', cfg_path)
    except Exception:
        print("Load cfg module failed", file=sys.stderr)
        sys.exit(1)

    i18n_msg_predicates = cfg_mod.i18n_msg_predicates
    msg_format_checkers = cfg_mod.msg_format_checkers
    black_list = cfg_mod.file_black_list

    debug = False
    if len(sys.argv) > 3:
        if sys.argv[3] == '-d':
            debug = True

    if os.path.isfile(input_path):
        sys.exit(check_i18n(input_path,
                            i18n_msg_predicates,
                            msg_format_checkers,
                            debug))

    error = 0
    for dirpath, dirs, files in os.walk(input_path):
        for f in files:
            if not f.endswith('.py'):
                continue
            input_file = os.path.join(dirpath, f)
            if is_file_in_black_list(black_list, input_file):
                continue
            if check_i18n(input_file,
                          i18n_msg_predicates,
                          msg_format_checkers,
                          debug):
                error = 1
    sys.exit(error)
