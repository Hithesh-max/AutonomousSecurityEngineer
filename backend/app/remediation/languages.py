"""Language-specific, non-executing parsers. Parsing is not compilation or testing."""
import ast
import importlib
import json
from pathlib import PurePosixPath

GRAMMARS = {'.js': ('javascript', 'language'), '.jsx': ('javascript', 'language'),
    '.ts': ('typescript', 'language_typescript'), '.tsx': ('typescript', 'language_tsx'),
    '.java': ('java', 'language'), '.c': ('c', 'language'), '.h': ('c', 'language'),
    '.cpp': ('cpp', 'language'), '.cc': ('cpp', 'language'), '.hpp': ('cpp', 'language'),
    '.html': ('html', 'language'), '.css': ('css', 'language')}


def language_for(path):
    return {'.py': 'Python', '.json': 'JSON', '.js': 'JavaScript', '.jsx': 'JavaScript',
            '.ts': 'TypeScript', '.tsx': 'TypeScript', '.java': 'Java', '.c': 'C',
            '.cpp': 'C++', '.cc': 'C++', '.h': 'C', '.hpp': 'C++', '.html': 'HTML', '.css': 'CSS', '.sql': 'SQL'}.get(PurePosixPath(path).suffix.lower(), 'Unknown')


def supports(path):
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in {'.py', '.json'}: return True
    if suffix not in GRAMMARS: return False
    try:
        import tree_sitter
        importlib.import_module('tree_sitter_' + GRAMMARS[suffix][0])
        return True
    except ImportError: return False


def syntax_check(path, content):
    language = language_for(path)
    try:
        if language == 'Python': ast.parse(content, filename=path)
        elif language == 'JSON': json.loads(content)
        else:
            suffix = PurePosixPath(path).suffix.lower()
            if not supports(path): return {'status': 'NOT_SUPPORTED', 'language': language, 'detail': 'No installed syntax adapter; manual review required.'}
            from tree_sitter import Language, Parser
            module, function = GRAMMARS[suffix]
            grammar = importlib.import_module('tree_sitter_' + module)
            parser = Parser(Language(getattr(grammar, function)()))
            tree = parser.parse(content.encode('utf-8'))
            if tree.root_node.has_error: raise ValueError('Syntax error')
    except (SyntaxError, ValueError, RecursionError):
        return {'status': 'FAIL', 'language': language, 'detail': 'Resulting file failed syntax validation.'}
    return {'status': 'PASS', 'language': language, 'detail': 'Language parser accepted syntax without executing code; no type/build or functional check.'}
