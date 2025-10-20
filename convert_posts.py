#!/usr/bin/env python3
"""
Convert Markdown blog posts to HTML for GitHub Pages deployment
"""

import os
import glob
import re

def md_to_html(md_file, html_file):
    """Convert markdown file to HTML with Phoenix Protocol styling"""
    
    with open(md_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Extract title from first H1
    title_match = re.search(r'^# (.+)$', content, re.MULTILINE)
    title = title_match.group(1) if title_match else "Phoenix Protocol - Threat Analysis"
    
    # Simple markdown to HTML conversion
    lines = content.split('\n')
    html_lines = []
    in_code_block = False
    in_list = False
    code_lang = ''
    
    for line in lines:
        # Skip empty lines at start
        if not html_lines and not line.strip():
            continue
        
        # Code blocks
        if line.startswith('```'):
            if not in_code_block:
                code_lang = line[3:].strip() or 'bash'
                html_lines.append(f'<pre><code class="{code_lang}">')
                in_code_block = True
            else:
                html_lines.append('</code></pre>')
                in_code_block = False
            continue
        
        if in_code_block:
            html_lines.append(line.replace('<', '&lt;').replace('>', '&gt;'))
            continue
        
        # Headers
        if line.startswith('# '):
            html_lines.append(f'<h1>{line[2:]}</h1>')
        elif line.startswith('## '):
            html_lines.append(f'<h2>{line[3:]}</h2>')
        elif line.startswith('### '):
            html_lines.append(f'<h3>{line[4:]}</h3>')
        elif line.startswith('#### '):
            html_lines.append(f'<h4>{line[5:]}</h4>')
        
        # Lists
        elif line.startswith('- ') or line.startswith('* '):
            if not in_list:
                html_lines.append('<ul>')
                in_list = True
            html_lines.append(f'<li>{line[2:]}</li>')
        elif re.match(r'^\d+\. ', line):
            if not in_list:
                html_lines.append('<ol>')
                in_list = True
            html_lines.append(f'<li>{line[line.index(". ")+2:]}</li>')
        else:
            if in_list:
                html_lines.append('</ul>' if lines[lines.index(line)-1].startswith(('-', '*')) else '</ol>')
                in_list = False
            
            # Bold and inline formatting
            if line.strip():
                line = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', line)
                line = re.sub(r'`(.+?)`', r'<code>\1</code>', line)
                html_lines.append(f'<p>{line}</p>')
            elif html_lines:  # Only add breaks if not at start
                html_lines.append('<br>')
    
    html_content = '\n'.join(html_lines)
    
    # Wrap in HTML template
    html_template = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - Phoenix Protocol</title>
    <meta name="description" content="Clinical cloud security threat analysis with CVE citations, detection strategies, and remediation priorities.">
    <link rel="stylesheet" href="../clinical.css">
</head>
<body>
    <header>
        <nav>
            <a href="../index.html" class="logo">🔥 Phoenix Protocol</a>
            <div class="nav-links">
                <a href="../index.html">Home</a>
                <a href="../blog.html">Blog</a>
                <a href="#reports">Reports</a>
            </div>
        </nav>
    </header>
    
    <div class="container">
        <article>
{html_content}
        </article>
        
        <hr>
        <p><a href="../blog.html">← Back to Blog</a> | <a href="mailto:architect@phoenixprotocol.security">Report Issues</a></p>
    </div>
    
    <script src="../asre_engine.js"></script>
</body>
</html>'''
    
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_template)


if __name__ == '__main__':
    # Change to blog_posts directory
    os.chdir('blog_posts')
    
    # Convert all markdown posts
    md_files = glob.glob('*.md')
    print(f"\nConverting {len(md_files)} markdown posts to HTML...\n")
    
    for md_file in md_files:
        html_file = md_file.replace('.md', '.html')
        md_to_html(md_file, html_file)
        print(f'✓ {md_file} → {html_file}')
    
    print(f"\n✓ All {len(md_files)} posts converted successfully!")
    print("Ready for GitHub Pages deployment.\n")
