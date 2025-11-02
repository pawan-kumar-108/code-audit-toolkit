#!/usr/bin/env python3
"""Codebase Health Scanner - Production-Grade Code Quality Analyzer"""
import os, re, json, hashlib, argparse, webbrowser
from pathlib import Path
from collections import defaultdict

class HealthScanner:
    DEFAULT_EXCLUDES = {'venv', 'env', '.venv', 'node_modules', '.git', '__pycache__', 
                        'dist', 'build', '.idea', '.vscode', 'target', 'vendor', '.next'}
    
    def __init__(self, path, exclude=None, verbose=False, include_defaults=True):
        self.path = Path(path).resolve()
        user_excludes = set(exclude or [])
        self.exclude = self.DEFAULT_EXCLUDES | user_excludes if include_defaults else user_excludes
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
        file_tree = self._build_file_tree()
        return {'health_score': self._calculate_health_score(), 'stats': dict(self.stats),
                'issues': self.issues, 'top_complex': self.functions[:10], 'file_tree': file_tree}
    
    def _build_file_tree(self):
        """Build hierarchical file structure for visualization"""
        tree = {}
        file_stats = defaultdict(lambda: {'functions': [], 'complexity': 0, 'lines': 0, 'issues': 0})
        
        for func in self.functions:
            filepath = func['file']
            parts = filepath.split('/')
            
            # Track file-level stats
            file_stats[filepath]['functions'].append(func['name'])
            file_stats[filepath]['complexity'] += func['complexity']
            file_stats[filepath]['lines'] += func['lines']
            
            # Build tree structure
            current = tree
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {'_files': [], '_complexity': 0, '_lines': 0}
                current = current[part]
            
            filename = parts[-1]
            if '_files' not in current:
                current['_files'] = []
            
            file_exists = any(f['name'] == filename for f in current['_files'])
            if not file_exists:
                current['_files'].append({
                    'name': filename, 
                    'complexity': file_stats[filepath]['complexity'], 
                    'lines': file_stats[filepath]['lines'],
                    'func_count': len(file_stats[filepath]['functions'])
                })
            current['_complexity'] = current.get('_complexity', 0) + func['complexity']
            current['_lines'] = current.get('_lines', 0) + func['lines']
        
        return {'tree': tree, 'file_stats': dict(file_stats)}
    
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
    """Export beautiful interactive HTML report"""
    s, t = report['stats'], report['file_tree']
    css = "*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,sans-serif;background:#f5f5f5;padding:20px;transition:background .3s}body.dark{background:#1a1a1a;color:#e0e0e0}.container{max-width:1200px;margin:0 auto;background:white;padding:30px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.1)}.dark .container{background:#2d2d2d}header{display:flex;justify-content:space-between;align-items:center;border-bottom:3px solid #3498db;padding-bottom:15px;margin-bottom:30px}h1{color:#2c3e50;font-size:28px}.dark h1{color:#e0e0e0}.theme-toggle{background:#3498db;color:white;border:none;padding:8px 16px;border-radius:6px;cursor:pointer}.score{font-size:64px;font-weight:bold;text-align:center;margin:30px 0;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin:30px 0}.metric{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;padding:20px;border-radius:10px}.metric strong{display:block;font-size:12px;opacity:.9;margin-bottom:5px}.metric span{font-size:28px;font-weight:bold}.section{margin:40px 0;padding:20px;background:#f8f9fa;border-radius:10px}.dark .section{background:#333}.section h2{color:#2c3e50;margin-bottom:20px}.dark .section h2{color:#e0e0e0}.search-box{width:100%;padding:12px;border:2px solid #ddd;border-radius:8px;font-size:16px;margin-bottom:20px}.dark .search-box{background:#444;border-color:#555;color:#e0e0e0}.tree{font-family:monospace;font-size:14px}.folder{cursor:pointer;padding:8px;margin:4px 0;border-radius:6px}.folder:hover{background:#e3f2fd}.dark .folder:hover{background:#404040}.complexity-bar{display:inline-block;height:20px;background:linear-gradient(90deg,#4caf50,#ffc107,#f44336);border-radius:4px;margin-left:10px}.issue{padding:12px;margin:8px 0;border-left:4px solid;border-radius:6px;display:flex;gap:10px}.critical{border-color:#e74c3c;background:#fadbd8}.dark .critical{background:#3d1f1f}.warning{border-color:#f39c12;background:#fef5e7}.dark .warning{background:#3d2f1f}.info{border-color:#3498db;background:#d6eaf8}.dark .info{background:#1f2d3d}.heatmap{display:grid;grid-template-columns:repeat(auto-fill,minmax(100px,1fr));gap:10px}.heatmap-cell{aspect-ratio:1;display:flex;align-items:center;justify-content:center;border-radius:8px;font-size:11px;font-weight:bold;color:white;text-align:center;padding:5px;cursor:pointer;transition:transform .2s}.heatmap-cell:hover{transform:scale(1.05)}.hidden{display:none}"
    
    html = f'<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Code Health Report</title><style>{css}</style></head><body><div class="container"><header><h1>🏥 Codebase Health Report</h1><button class="theme-toggle" onclick="toggleTheme()">🌓</button></header><div class="score">{report["health_score"]}/100</div><div class="metrics">'
    
    metrics_data = [('Total Lines', s['total_lines']), ('Functions', s['functions']), ('Code Lines', s['code_lines']), ('Classes', s['classes']), ('Files', s['files']), ('Comments', f"{s['comment_lines']/max(s['code_lines'],1)*100:.1f}%")]
    for label, val in metrics_data:
        display_val = f"{val:,}" if isinstance(val, int) else val
        html += f'<div class="metric"><strong>{label}</strong><span>{display_val}</span></div>'
    
    html += '</div><div class="section"><h2>🗺️ Complexity Heatmap</h2><div class="heatmap" id="heatmap"></div></div><div class="section"><h2>📂 Interactive File Tree</h2><input type="text" class="search-box" id="searchBox" placeholder="🔍 Search..." onkeyup="filterContent()"><div class="tree" id="fileTree"></div></div><div class="section"><h2>🔥 Top Complex Functions</h2><div>'
    
    for f in report['top_complex'][:15]:
        sev = 'critical' if f['complexity']>30 else 'warning' if f['complexity']>15 else 'info'
        html += f'<div class="issue {sev}"><span style="font-size:20px">📄</span><div><strong>{f["file"]}::{f["name"]}</strong><br>Complexity: {f["complexity"]} | Lines: {f["lines"]}</div></div>'
    
    html += '</div></div><div class="section"><h2>⚠️ Issues</h2><div>'
    for i in report['issues']['critical'][:10]:
        html += f'<div class="issue critical"><span style="font-size:20px">🔴</span><div>{i}</div></div>'
    for i in report['issues']['warning'][:15]:
        html += f'<div class="issue warning"><span style="font-size:20px">🟡</span><div>{i}</div></div>'
    
    js = f"const d={json.dumps(t)},c={json.dumps(report['top_complex'][:20])};function toggleTheme(){{document.body.classList.toggle('dark');localStorage.setItem('theme',document.body.classList.contains('dark')?'dark':'light')}}function buildTree(o,p=''){{let h='';for(let k in o){{if(k.startsWith('_'))continue;const f=o[k],cx=f._complexity||0,ln=f._lines||0,w=Math.min(200,cx*2);h+=`<div class='folder' onclick='toggleFolder(this)'><span>📁</span> ${{k}}<span class='complexity-bar' style='width:${{w}}px'></span><span style='margin-left:10px;color:#888;font-size:12px'>(${{ln}} lines)</span></div>`;h+=`<div class='hidden' style='margin-left:30px'>${{buildTree(f,p+k+'/')}}</div>`;if(f._files)f._files.forEach(x=>h+=`<div style='margin-left:30px;padding:5px'>📄 ${{x.name}} <span style='color:#888'>(complexity: ${{x.complexity}})</span></div>`)}}return h}}function toggleFolder(e){{const n=e.nextElementSibling;if(n){{n.classList.toggle('hidden');e.querySelector('span').textContent=n.classList.contains('hidden')?'📁':'📂'}}}}function buildHeatmap(){{const h=document.getElementById('heatmap');c.forEach(f=>{{const el=document.createElement('div');el.className='heatmap-cell';const i=Math.min(f.complexity/50,1),col=`hsl(${{120-i*120}},70%,50%)`;el.style.background=col;el.innerHTML=`${{f.file.split('/').pop()}}<br><small>${{f.complexity}}</small>`;el.title=`${{f.file}}::${{f.name}}\\nComplexity: ${{f.complexity}}`;h.appendChild(el)}})}}function filterContent(){{const q=document.getElementById('searchBox').value.toLowerCase();document.querySelectorAll('.folder,.issue').forEach(e=>e.style.display=e.textContent.toLowerCase().includes(q)?'':'none')}}document.getElementById('fileTree').innerHTML=buildTree(d);buildHeatmap();if(localStorage.getItem('theme')==='dark')document.body.classList.add('dark');"
    
    html += f'</div></div></div><script>{js}</script></body></html>'
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)

def main():
    parser = argparse.ArgumentParser(description='Codebase Health Scanner')
    parser.add_argument('path', help='Path to scan')
    parser.add_argument('--exclude', help='Comma-separated dirs to exclude (adds to defaults)', default='')
    parser.add_argument('--no-defaults', action='store_true', help='Disable default exclusions')
    parser.add_argument('--format', choices=['terminal', 'json', 'html'], default='terminal')
    parser.add_argument('--output', help='Output file (for json/html)')
    parser.add_argument('--open', action='store_true', help='Auto-open HTML report in browser')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()
    
    try:
        exclude = [e.strip() for e in args.exclude.split(',') if e.strip()]
        scanner = HealthScanner(args.path, exclude=exclude, verbose=args.verbose, 
                               include_defaults=not args.no_defaults)
        
        if args.verbose and not args.no_defaults:
            print(f"📂 Auto-excluding: {', '.join(sorted(HealthScanner.DEFAULT_EXCLUDES))}")
        
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
            if args.open:
                print(f"🌐 Opening in browser...")
                webbrowser.open(f'file://{os.path.abspath(output)}')
            else:
                print(f"💡 Tip: Use --open flag to auto-open in browser next time!")
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