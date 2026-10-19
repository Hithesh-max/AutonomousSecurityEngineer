"""Deterministic source metadata. Never imports or runs repository code."""
import ast
from collections import Counter
from dataclasses import dataclass, field, asdict
import hashlib
import json
from pathlib import Path
import re
import time
import tomllib

IGNORED_DIRS = {'.git', 'node_modules', 'venv', '.venv', 'env', 'dist', 'build', '__pycache__', '.cache', '.pytest_cache', 'coverage', 'vendor'}
IGNORED_CONFIG = {'.semgrepignore', '.gitleaksignore', '.gitleaks.toml', 'gitleaks.toml', '.gitignore'}
EXTENSIONS = {'.c': 'C', '.h': 'C', '.cpp': 'C++', '.hpp': 'C++', '.cc': 'C++', '.py': 'Python', '.js': 'JavaScript', '.jsx': 'JavaScript', '.ts': 'TypeScript', '.tsx': 'TypeScript', '.html': 'HTML', '.css': 'CSS', '.sql': 'SQL', '.sh': 'Shell', '.go': 'Go', '.java': 'Java', '.rs': 'Rust'}
FRAMEWORK_IMPORTS = {'fastapi': 'FastAPI', 'flask': 'Flask', 'django': 'Django', 'express': 'Express', 'react': 'React', 'next': 'Next.js', '@angular/core': 'Angular', 'vue': 'Vue'}
MANIFESTS = {'package.json', 'package-lock.json', 'requirements.txt', 'pyproject.toml', 'Pipfile', 'Pipfile.lock', 'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'}


@dataclass
class Intelligence:
    files: list[dict] = field(default_factory=list)
    languages: list[dict] = field(default_factory=list)
    frameworks: list[dict] = field(default_factory=list)
    manifests: list[dict] = field(default_factory=list)
    dependencies: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    ignored_files: int = 0


def eligible_files(root: Path):
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Managed source workspace is unavailable.')
    for directory, dirs, names in __import__('os').walk(root, followlinks=False):
        parent = Path(directory)
        for name in dirs:
            if (parent / name).is_symlink():
                raise ValueError('Workspace contains a symlink.')
        dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIRS)
        for name in sorted(names):
            path = parent / name
            if path.is_symlink() or not path.is_file():
                raise ValueError('Workspace contains an unsafe file.')
            if name not in IGNORED_CONFIG:
                yield path


def _requirement(value: str):
    match = re.match(r'^\s*([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(.*)$', value)
    if not match:
        return None
    name, constraint = match.groups()
    # Credentials in direct URLs are never persisted.
    if '@' in constraint or '://' in constraint:
        return {'name': name, 'version': None, 'constraint': 'DIRECT_REFERENCE_REDACTED'}
    constraint = constraint.split(';', 1)[0].strip()
    return {'name': name, 'version': constraint[2:].strip() if constraint.startswith('==') else None, 'constraint': constraint or None}


def parse_manifest(path: str, text: str) -> list[dict]:
    name = Path(path).name
    dependencies = []
    def add(ecosystem, item, group, locked=False):
        if item and len(dependencies) >= 2000:
            raise RuntimeError('Per-manifest dependency limit exceeded.')
        if item:
            if not isinstance(item.get('name'), str) or not item['name'] or len(item['name']) > 255:
                raise ValueError('Invalid dependency name')
            if any(item.get(key) is not None and not isinstance(item.get(key), str) for key in ['version', 'constraint']):
                raise ValueError('Invalid dependency version')
            for key in ['name', 'version', 'constraint']:
                value = item.get(key)
                if isinstance(value, str):
                    item[key] = 'DIRECT_REFERENCE_REDACTED' if '://' in value or 'git@' in value else value[:255]
            dependencies.append({**item, 'ecosystem': ecosystem, 'manifest': path, 'group': group, 'locked': locked})
    if name == 'requirements.txt':
        for line in text.splitlines():
            if line.strip() and not line.lstrip().startswith(('#', '-')):
                add('pypi', _requirement(line.split(' #', 1)[0]), 'runtime')
    elif name == 'package.json':
        data = json.loads(text)
        if not isinstance(data, dict): raise ValueError('Invalid manifest')
        for group in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
            values = data.get(group, {})
            if not isinstance(values, dict): raise ValueError('Invalid dependency object')
            for dependency, constraint in values.items():
                if isinstance(constraint, str):
                    add('npm', {'name': dependency, 'version': constraint if re.fullmatch(r'\d+\.\d+\.\d+(?:-[\w.]+)?', constraint) else None,
                                'constraint': 'DIRECT_REFERENCE_REDACTED' if '://' in constraint or constraint.startswith('git@') else constraint}, group)
    elif name == 'package-lock.json':
        data = json.loads(text)
        if not isinstance(data, dict): raise ValueError('Invalid manifest')
        packages = data.get('packages', {})
        if isinstance(packages, dict):
            for location, info in packages.items():
                if location and isinstance(info, dict) and isinstance(info.get('version'), str):
                    dependency = info.get('name') or location.rsplit('node_modules/', 1)[-1]
                    add('npm', {'name': dependency, 'version': info['version'], 'constraint': None}, 'lock', True)
        # Lockfile v1 is not recursively expanded in this foundation.
    elif name in {'pyproject.toml', 'Pipfile'}:
        data = tomllib.loads(text)
        project = data.get('project', {})
        if isinstance(project, dict):
            if not isinstance(project.get('dependencies', []), list) or not isinstance(project.get('optional-dependencies', {}), dict):
                raise ValueError('Invalid project dependencies')
            for value in project.get('dependencies', []):
                if isinstance(value, str): add('pypi', _requirement(value), 'runtime')
            for group, values in project.get('optional-dependencies', {}).items():
                if not isinstance(values, list): raise ValueError('Invalid optional dependencies')
                for value in values:
                    if isinstance(value, str): add('pypi', _requirement(value), group)
        poetry = data.get('tool', {}).get('poetry', {}).get('dependencies', {})
        for dependency, value in poetry.items():
            if dependency == 'python': continue
            constraint = value if isinstance(value, str) else value.get('version') if isinstance(value, dict) else None
            add('pypi', {'name': dependency, 'version': None, 'constraint': constraint}, 'poetry')
        for group in ['packages', 'dev-packages']:
            for dependency, value in data.get(group, {}).items():
                add('pypi', {'name': dependency, 'version': None, 'constraint': value if isinstance(value, str) else None}, group)
    elif name == 'Pipfile.lock':
        data = json.loads(text)
        for group in ['default', 'develop']:
            for dependency, info in data.get(group, {}).items():
                if isinstance(info, dict):
                    value = info.get('version', '')
                    add('pypi', {'name': dependency, 'version': value[2:] if value.startswith('==') else None, 'constraint': value}, group, True)
    return dependencies


def python_metadata(text: str):
    tree = ast.parse(text)
    imports, functions, classes, routes = [], [], [], []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import): imports.extend(alias.name for alias in node.names)
        if isinstance(node, ast.ImportFrom) and node.module: imports.append(node.module)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if len(functions) < 200: functions.append({'name': node.name, 'line': node.lineno, 'end_line': node.end_lineno})
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute) and decorator.args and isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str):
                    method = decorator.func.attr.lower()
                    if method in {'get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'route'} and len(routes) < 100:
                        routes.append({'path': decorator.args[0].value, 'method': method.upper() if method != 'route' else 'UNRESOLVED', 'function': node.name, 'line': node.lineno, 'confidence': 'MEDIUM', 'prefix_resolved': False})
        if isinstance(node, ast.ClassDef) and len(classes) < 200:
            classes.append({'name': node.name, 'line': node.lineno, 'end_line': node.end_lineno})
    return imports[:200], functions, classes, routes


def inspect_repository(root: Path, *, max_files=3000, max_bytes=100 * 1024 * 1024, seconds=60) -> Intelligence:
    result = Intelligence()
    deadline = time.monotonic() + seconds
    stats, evidence, total = Counter(), {}, 0
    for path in eligible_files(root):
        if time.monotonic() > deadline: raise ValueError('Indexing time limit exceeded.')
        if len(result.files) >= max_files: raise ValueError('Indexing file limit exceeded.')
        relative = path.relative_to(root).as_posix()
        size = path.stat().st_size
        total += size
        if total > max_bytes or size > 5 * 1024 * 1024: raise ValueError('Indexing byte limit exceeded.')
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        text = None
        if b'\0' not in raw and len(raw) <= 1024 * 1024:
            try: text = raw.decode('utf-8')
            except UnicodeDecodeError: pass
        language = EXTENSIONS.get(path.suffix.lower()) if text is not None else None
        confidence = 'LOW' if language else None
        imports, functions, classes, routes = [], [], [], []
        if text is not None:
            head = text[:4096]
            if head.startswith('#!') and 'python' in head.splitlines()[0]: language, confidence = 'Python', 'HIGH'
            elif head.startswith('#!') and 'node' in head.splitlines()[0]: language, confidence = 'JavaScript', 'HIGH'
            if language == 'Python' and size <= 512 * 1024:
                try:
                    imports, functions, classes, routes = python_metadata(text)
                    confidence = 'HIGH'
                except (SyntaxError, RecursionError, ValueError): result.warnings.append('PYTHON_PARSE_INCOMPLETE')
            elif language in {'JavaScript', 'TypeScript'}:
                imports = re.findall(r'(?:from\s+[\'"]|require\(\s*[\'"])([^\'"]+)', text)[:200]
                if re.search(r'\b(import|export|function|const|let|class)\b', head): confidence = 'MEDIUM'
                functions = [{'name': m.group(1), 'line': text.count('\n', 0, m.start()) + 1} for m in list(re.finditer(r'\bfunction\s+(\w+)\s*\(', text))[:200]]
                classes = [{'name': m.group(1), 'line': text.count('\n', 0, m.start()) + 1} for m in list(re.finditer(r'\bclass\s+(\w+)', text))[:200]]
                routes = [{'path': m.group(2), 'method': m.group(1).upper(), 'line': text.count('\n', 0, m.start()) + 1, 'confidence': 'LOW', 'prefix_resolved': False} for m in list(re.finditer(r'\.(get|post|put|patch|delete)\(\s*[\'"]([^\'"]+)[\'"]', text))[:100]]
            elif not language and re.search(r'<(?:!doctype\s+html|html|body)\b', head, re.I): language, confidence = 'HTML', 'MEDIUM'
            elif not language and re.search(r'\bCREATE\s+TABLE\b', head, re.I): language, confidence = 'SQL', 'MEDIUM'
            for imported in imports:
                for module, framework in FRAMEWORK_IMPORTS.items():
                    if imported == module or imported.startswith(module + '.') or imported.startswith(module + '/'):
                        evidence.setdefault(framework, set()).add((relative, 'ast_import' if language == 'Python' else 'heuristic_import'))
            if path.name in MANIFESTS:
                try:
                    deps = parse_manifest(relative, text)
                    if path.name == 'requirements.txt' and any(line.lstrip().startswith('-') for line in text.splitlines()):
                        result.warnings.append('REQUIREMENTS_DIRECTIVES_NOT_RESOLVED')
                    if path.name == 'package-lock.json' and json.loads(text).get('lockfileVersion') == 1:
                        result.warnings.append('LOCKFILE_V1_NOT_RESOLVED')
                    result.manifests.append({'path': relative, 'dependency_count': len(deps), 'status': 'PARSED' if path.name not in {'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'} else 'DETECTED_ONLY'})
                    result.dependencies.extend(deps)
                    if len(result.dependencies) > 5000: raise RuntimeError('Dependency limit exceeded.')
                    for dep in deps:
                        framework = FRAMEWORK_IMPORTS.get(dep['name'].lower())
                        if framework: evidence.setdefault(framework, set()).add((relative, 'dependency'))
                except (ValueError, TypeError, AttributeError, RecursionError):
                    result.manifests.append({'path': relative, 'status': 'PARSE_FAILED', 'dependency_count': 0})
                    result.warnings.append('MANIFEST_PARSE_INCOMPLETE')
        elif path.name in MANIFESTS:
            result.manifests.append({'path': relative, 'status': 'TOO_LARGE_OR_BINARY', 'dependency_count': 0})
            result.warnings.append('MANIFEST_NOT_PARSED')
        if len(imports) >= 200 or len(functions) >= 200 or len(classes) >= 200 or len(routes) >= 100:
            result.warnings.append('CODE_INDEX_BOUNDED')
        imports = ['DIRECT_REFERENCE_REDACTED' if '://' in value or 'git@' in value else value[:255] for value in imports]
        for route in routes:
            route['path'] = route['path'][:500]
        if language:
            stats[language] += size
        result.files.append({'path': relative, 'language': language, 'language_confidence': confidence, 'size': size,
                             'sha256': digest, 'functions': functions, 'classes': classes, 'imports': imports,
                             'routes': routes, 'is_text': text is not None, 'line_count': len(text.splitlines()) if text is not None else None})
    counted = sum(stats.values())
    result.languages = [{'language': language, 'bytes': size, 'percentage': round(100 * size / counted, 2) if counted else 0,
                         'files': sum(f['language'] == language for f in result.files)} for language, size in stats.most_common()]
    result.frameworks = [{'framework': name, 'confidence': 'HIGH' if any(kind == 'ast_import' for _, kind in proofs) else 'MEDIUM',
                          'evidence': [{'file': file, 'kind': kind} for file, kind in sorted(proofs)[:20]]} for name, proofs in sorted(evidence.items())]
    result.warnings = sorted(set(result.warnings))
    if len(json.dumps(asdict(result), ensure_ascii=True).encode()) > 4 * 1024 * 1024:
        raise RuntimeError('Source index metadata limit exceeded.')
    return result
