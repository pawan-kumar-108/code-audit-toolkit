#!/usr/bin/env python3
"""Codebase Health Scanner - Production-Grade Code Quality Analyzer"""
import os, re, json, hashlib, argparse
from pathlib import Path
from collections import defaultdict

class HealthScanner:
    def __init__(self, path, exclude=None, verbose=False):
        self.path = Path(path).resolve()
        self.exclude = set(exclude or [])
        self.verbose = verbose
        self.stats = defaultdict(int)
        self.issues = {'critical': [], 'warning': [], 'info': []}
        self.functions = []
        self.file_hashes = defaultdict(list)
        
    def scan(self):
        """Main scan orchestrator"""
        if not self.path.exists():
            raise ValueError(f"Path does not exist: {self.path}")
        files = self._collect_files()
        for idx, file in enumerate(files, 1):
            if self.verbose: self._print_progress(idx, len(files))
            self._analyze_file(file)
        self._detect_duplicates()
        return self._generate_report()
    
    def _collect_files(self):
        """Collect all code files, skip excluded dirs"""
        extensions = {'.py', '.js', '.java', '.c', '.cpp', '.h', '.go', '.rb', '.php'}
        files = []
        try:
            if self.path.is_file():
                return [self.path] if self.path.suffix in extensions else []
            for item in self.path.rglob('*'):
                try:
                    if item.is_file() and item.suffix in extensions:
                        if not any(ex in item.parts for ex in self.exclude):
                            files.append(item)
                except (PermissionError, OSError): continue
        except (PermissionError, OSError) as e:
            if self.verbose: print(f"Warning: {e}")
        return files
    
    def _analyze_file(self, filepath):
        """Analyze single file for metrics and issues"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except (OSError, UnicodeDecodeError): return
        
        self.stats['files'] += 1
        self.stats['total_lines'] += len(lines)
        
        comment_chars = {'#'} if filepath.suffix == '.py' else {'//', '/*', '*'}
        for line in lines:
            stripped = line.strip()
            if not stripped: self.stats['blank_lines'] += 1
            elif any(stripped.startswith(c) for c in comment_chars): self.stats['comment_lines'] += 1
            else: self.stats['code_lines'] += 1
        
        self._analyze_functions(content, filepath)
        self._analyze_security(content, filepath)
        self._store_hash(content, filepath)
    
    def _analyze_functions(self, content, filepath):
        """Extract and analyze functions/methods"""
        patterns = {'.py': r'def\s+(\w+)\s*\(', '.js': r'function\s+(\w+)\s*\(|(\w+)\s*[=:]\s*\([^)]*\)\s*=>',
                   '.java': r'(public|private|protected)?\s*\w+\s+(\w+)\s*\(', 
                   '.c': r'\w+\s+(\w+)\s*\([^)]*\)\s*\{', '.cpp': r'\w+\s+(\w+)\s*\([^)]*\)\s*\{'}
        pattern = patterns.get(filepath.suffix)
        if not pattern: return
        
        for match in re.finditer(pattern, content):
            self.stats['functions'] += 1
            func_name = match.group(1) or match.group(2) or 'unknown'
            func_content = self._extract_function_body(content[match.start():], filepath.suffix)
            lines = len(func_content.split('\n'))
            complexity = self._calculate_complexity(func_content)
            
            self.functions.append({'name': func_name, 'file': str(filepath.relative_to(self.path)), 
                                  'lines': lines, 'complexity': complexity})
            
            if lines > 50:
                self.issues['warning'].append(f"Long function: {filepath.name}::{func_name} ({lines} lines)")
            if complexity > 15:
                self.issues['warning'].append(f"High complexity: {filepath.name}::{func_name} (complexity: {complexity})")
    
    def _extract_function_body(self, content, ext):
        """Extract function body (simplified)"""
        lines = content.split('\n')
        body, brace_count, indent_level = [], 0, None
        
        for line in lines[:200]:
            stripped = line.strip()
            if ext == '.py':
                if indent_level is None:
                    if stripped and not stripped.startswith('def'):
                        indent_level = len(line) - len(line.lstrip())
                elif stripped and len(line) - len(line.lstrip()) <= indent_level:
                    if not stripped.startswith(('def', 'class', '@')): break
                body.append(line)
            else:
                brace_count += line.count('{') - line.count('}')
                body.append(line)
                if brace_count == 0 and '{' in content[:len('\n'.join(body))]: break
        return '\n'.join(body[:100])
    
    def _calculate_complexity(self, code):
        """Calculate cyclomatic complexity"""
        complexity = 1
        for kw in ['if', 'elif', 'else', 'for', 'while', 'case', 'catch']:
            complexity += len(re.findall(rf'\b{kw}\b', code))
        complexity += code.count('&&') + code.count('||') + code.count('?')
        return complexity
    
    def _analyze_security(self, content, filepath):
        """Detect security issues and code smells"""
        rel_path = str(filepath.relative_to(self.path))
        patterns = [(r'password\s*=\s*["\'][^"\']+["\']', 'Hardcoded password', 'critical'),
                   (r'api[_-]?key\s*=\s*["\'][^"\']+["\']', 'Hardcoded API key', 'critical'),
                   (r'secret\s*=\s*["\'][^"\']+["\']', 'Hardcoded secret', 'critical'),
                   (r'eval\s*\(', 'Dangerous eval() usage', 'critical'),
                   (r'exec\s*\(', 'Dangerous exec() usage', 'critical'),
                   (r'SELECT.*FROM.*WHERE.*["\'].*\+', 'Potential SQL injection', 'critical'),
                   (r'TODO|FIXME|HACK|XXX', 'Code smell comment', 'info')]
        
        for pattern, desc, severity in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                self.issues[severity].append(f"{desc} in {rel_path}:{line_num}")
        
        if re.search(r'class\s+\w+', content): self.stats['classes'] += 1
    
    def _store_hash(self, content, filepath):
        """Store file hash for duplicate detection"""
        normalized = re.sub(r'\s+', '', content)
        if len(normalized) > 50:
            file_hash = hashlib.md5(normalized.encode()).hexdigest()
            self.file_hashes[file_hash].append(str(filepath.relative_to(self.path)))
    
    def _detect_duplicates(self):
        """Find duplicate code blocks"""
        for file_hash, files in self.file_hashes.items():
            if len(files) > 1:
                self.issues['info'].append(f"Duplicate code in: {', '.join(files[:3])}")
    
    def _calculate_health_score(self):
        """Calculate overall health score (0-100)"""
        score = 100 - len(self.issues['critical']) * 10 - len(self.issues['warning']) * 3 - len(self.issues['info']) * 0.5
        if self.stats['code_lines'] > 0:
            if self.stats['comment_lines'] / self.stats['code_lines'] < 0.05: score -= 10
        avg_complexity = sum(f['complexity'] for f in self.functions) / max(len(self.functions), 1)
        if avg_complexity > 10: score -= 5
        return max(0, min(100, int(score)))
    
    def _generate_report(self):
        """Generate final report"""
        self.functions.sort(key=lambda x: x['complexity'], reverse=True)
        return {'health_score': self._calculate_health_score(), 'stats': dict(self.stats),
                'issues': self.issues, 'top_complex': self.functions[:10]}
    
    def _print_progress(self, current, total):
        """Print progress bar"""
        percent, bar_length = int((current / total) * 100), 40
        filled = int(bar_length * current / total)
        print(f"\r🔍 Scanning: {'█' * filled}{'░' * (bar_length - filled)} {percent}% | {current}/{total} files", end='', flush=True)

def format_terminal_report(report):
    """Format report for terminal output with colors"""
    health, stats, issues, top = report['health_score'], report['stats'], report['issues'], report['top_complex']
    stars = '⭐' * (health // 20)
    
    output = ["\n" + "═" * 60, "          CODEBASE HEALTH SCANNER v1.0", "═" * 60,
              f"\n📊 OVERALL HEALTH SCORE: {health}/100 {stars}\n", "📈 CODE METRICS:",
              f"  Total Lines:        {stats['total_lines']:,}",
              f"  Code Lines:         {stats['code_lines']:,}",
              f"  Comment Lines:      {stats['comment_lines']:,} ({stats['comment_lines']/max(stats['code_lines'],1)*100:.1f}%)",
              f"  Blank Lines:        {stats['blank_lines']:,}",
              f"\n  Functions:          {stats['functions']:,}",
              f"  Classes:            {stats['classes']:,}",
              f"  Files Analyzed:     {stats['files']:,}"]
    
    if top:
        output.append("\n🔥 COMPLEXITY HOT SPOTS:")
        for i, func in enumerate(top[:5], 1):
            filled = min(20, int(func['complexity'] / 5))
            output.append(f"  {i}. {'█' * filled}{'░' * (20 - filled)} {func['file']}::{func['name']} - {func['complexity']}")
    
    output.extend(["\n⚠️  ISSUES FOUND:", f"  🔴 Critical ({len(issues['critical'])}):",
                  *[f"     - {issue}" for issue in issues['critical'][:5]],
                  f"\n  🟡 Warnings ({len(issues['warning'])}):",
                  *[f"     - {issue}" for issue in issues['warning'][:5]],
                  f"\n  💡 Info ({len(issues['info'])}):",
                  f"     - {len(issues['info'])} code smell comments and duplicates found"])
    return '\n'.join(output)

def export_html_report(report, output_file):
    """Export beautiful HTML report"""
    s = report['stats']
    html = f"""<!DOCTYPE html>
<html><head><title>Code Health Report</title>
<style>body{{font-family:Arial,sans-serif;margin:40px;background:#f5f5f5}}
.container{{max-width:1000px;margin:0 auto;background:white;padding:30px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}}
h1{{color:#2c3e50;border-bottom:3px solid #3498db;padding-bottom:10px}}
.score{{font-size:48px;color:#27ae60;text-align:center;margin:20px 0}}
.metrics{{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin:20px 0}}
.metric{{background:#ecf0f1;padding:15px;border-radius:5px}}
.issue{{padding:10px;margin:5px 0;border-left:4px solid;}}
.critical{{border-color:#e74c3c;background:#fadbd8}}
.warning{{border-color:#f39c12;background:#fef5e7}}
.info{{border-color:#3498db;background:#d6eaf8}}
</style></head><body><div class="container">
<h1>🏥 Codebase Health Report</h1>
<div class="score">{report['health_score']}/100</div>
<div class="metrics">
<div class="metric"><strong>Total Lines:</strong> {s['total_lines']:,}</div>
<div class="metric"><strong>Functions:</strong> {s['functions']:,}</div>
<div class="metric"><strong>Code Lines:</strong> {s['code_lines']:,}</div>
<div class="metric"><strong>Classes:</strong> {s['classes']:,}</div>
</div>
<h2>🔥 Top Complex Functions</h2>"""
    
    for func in report['top_complex'][:10]:
        html += f"<div class='issue info'>{func['file']}::{func['name']} - Complexity: {func['complexity']}</div>"
    
    html += "<h2>⚠️ Issues</h2>"
    for issue in report['issues']['critical'][:10]:
        html += f"<div class='issue critical'>🔴 {issue}</div>"
    for issue in report['issues']['warning'][:10]:
        html += f"<div class='issue warning'>🟡 {issue}</div>"
    html += "</div></body></html>"
    
    with open(output_file, 'w') as f:
        f.write(html)

def main():
    parser = argparse.ArgumentParser(description='Codebase Health Scanner')
    parser.add_argument('path', help='Path to scan')
    parser.add_argument('--exclude', help='Comma-separated dirs to exclude', default='')
    parser.add_argument('--format', choices=['terminal', 'json', 'html'], default='terminal')
    parser.add_argument('--output', help='Output file (for json/html)')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()
    
    try:
        exclude = [e.strip() for e in args.exclude.split(',') if e.strip()]
        scanner = HealthScanner(args.path, exclude=exclude, verbose=args.verbose)
        print(f"\n🔍 Scanning: {args.path}")
        report = scanner.scan()
        if args.verbose: print()
        
        if args.format == 'terminal':
            print(format_terminal_report(report))
        elif args.format == 'json':
            output = args.output or 'health_report.json'
            with open(output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n✅ Report saved: {output}")
        elif args.format == 'html':
            output = args.output or 'health_report.html'
            export_html_report(report, output)
            print(f"\n✅ HTML report saved: {output}")
    except ValueError as e:
        print(f"\n❌ Error: {e}")
        return 1
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return 1
    return 0

if __name__ == '__main__':
    exit(main())