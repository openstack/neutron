import compiler
import re


def is_log_callfunc(n):
    """LOG.xxx('hello %s' % xyz) and LOG('hello')"""
    if isinstance(n.parent, compiler.ast.Mod):
        n = n.parent
    if isinstance(n.parent, compiler.ast.CallFunc):
        if isinstance(n.parent.node, compiler.ast.Getattr):
            if isinstance(n.parent.node.getChildNodes()[0],
                          compiler.ast.Name):
                if n.parent.node.getChildNodes()[0].name == 'LOG':
                    return True
    return False


def is_log_i18n_msg_with_mod(n):
    """LOG.xxx("Hello %s" % xyz) should be LOG.xxx("Hello %s", xyz)"""
    if not isinstance(n.parent.parent, compiler.ast.Mod):
        return False
    n = n.parent.parent
    if isinstance(n.parent, compiler.ast.CallFunc):
        if isinstance(n.parent.node, compiler.ast.Getattr):
            if isinstance(n.parent.node.getChildNodes()[0],
                          compiler.ast.Name):
                if n.parent.node.getChildNodes()[0].name == 'LOG':
                    return True
    return False


def is_wrong_i18n_format(n):
    """Check _('hello %s' % xyz)"""
    if isinstance(n.parent, compiler.ast.Mod):
        n = n.parent
    if isinstance(n.parent, compiler.ast.CallFunc):
        if isinstance(n.parent.node, compiler.ast.Name):
            if n.parent.node.name == '_':
                return True
    return False


"""
Used for check message need be localized or not.
(predicate_func, action, message)
"""
i18n_msg_predicates = [
    # Skip ['hello world', 1]
    (lambda n: isinstance(n.parent, compiler.ast.List), 'skip', ''),
    # Skip {'hellow world', 1}
    (lambda n: isinstance(n.parent, compiler.ast.Dict), 'skip', ''),
    # Skip msg['hello world']
    (lambda n: isinstance(n.parent, compiler.ast.Subscript), 'skip', ''),
    # Skip doc string
    (lambda n: isinstance(n.parent, compiler.ast.Discard), 'skip', ''),
    # Skip msg = "hello", in normal, message should more than one word
    (lambda n: len(n.value.strip().split(' ')) <= 1, 'skip', ''),
    # Skip msg = 'hello world' + vars + 'world hello'
    (lambda n: isinstance(n.parent, compiler.ast.Add), 'skip', ''),
    # Skip xml markers msg = "<test></test>"
    (lambda n: len(re.compile("</.*>").findall(n.value)) > 0, 'skip', ''),
    # Skip sql statement
    (lambda n: len(
        re.compile("^SELECT.*FROM", flags=re.I).findall(n.value)) > 0,
     'skip', ''),
    # LOG.xxx()
    (is_log_callfunc, 'error', 'Message must be localized'),
    # _('hello %s' % xyz) should be _('hello %s') % xyz
    (is_wrong_i18n_format, 'error',
     ("Message format was wrong, _('hello %s' % xyz) "
      "should be _('hello %s') % xyz")),
    # default
    (lambda n: True, 'warn', 'Message might need localized')
]


"""
Used for checking message format. (checker_func, message)
"""
msg_format_checkers = [
    # If message contain more than on format specifier, it should use
    # mapping key
    (lambda n: len(re.compile("%[bcdeEfFgGnosxX]").findall(n.value)) > 1,
     "The message shouldn't contain more than one format specifier"),
    # Check capital
    (lambda n: n.value.split(' ')[0].count('_') == 0 and
     n.value[0].isalpha() and
     n.value[0].islower(),
     "First letter must be capital"),
    (is_log_i18n_msg_with_mod,
     'LOG.xxx("Hello %s" % xyz) should be LOG.xxx("Hello %s", xyz)')
]


file_black_list = ["./neutron/tests/unit",
                   "./neutron/openstack",
                   "./neutron/plugins/bigswitch/tests"]
