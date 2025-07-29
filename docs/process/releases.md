# Release Process

This document outlines the complete release process for Nginx Security Monitor, including preparation,
testing, deployment, and post-release activities.

## Release Types

- **Major Release** (X.0.0): Breaking changes, major new features
- **Minor Release** (x.Y.0): New features, enhancements, deprecations
- **Patch Release** (x.y.Z): Bug fixes, security patches, documentation updates
- **Hotfix Release** (x.y.z-hotfix.N): Critical bug fixes or security patches

## Release Schedule

- **Major Releases**: Quarterly (March, June, September, December)
- **Minor Releases**: Monthly or as needed
- **Patch Releases**: Bi-weekly or as needed
- **Hotfix Releases**: As needed for critical issues

## Pre-Release Checklist

### 1. Development Complete ✅

- [ ] All planned features implemented
- [ ] Code review completed for all changes
- [ ] Documentation updated
- [ ] Breaking changes documented in CHANGELOG.md

### 2. Testing ✅

- [ ] All unit tests passing
- [ ] Integration tests passing
- [ ] Performance tests completed
- [ ] Security scan completed
- [ ] Manual testing in staging environment
- [ ] Backwards compatibility verified (for minor/patch releases)

### 3. Documentation ✅

- [ ] CHANGELOG.md updated with all changes
- [ ] Version numbers updated in all files
- [ ] API documentation updated
- [ ] Migration guide created (if needed)
- [ ] Release notes drafted

### 4. Dependencies ✅

- [ ] Dependency vulnerabilities checked
- [ ] Dependency licenses verified
- [ ] Requirements.txt updated
- [ ] Docker base images updated

## Release Preparation

### 1. Version Bumping

```bash
# Use semantic versioning
# scripts/bump_version.py

#!/usr/bin/env python3
import re
import sys
import subprocess
from pathlib import Path

def bump_version(version_type):
    """Bump version number in all relevant files"""
    
    # Read current version from setup.py
    setup_py = Path("setup.py")
    content = setup_py.read_text()
    
    # Extract current version
    version_match = re.search(r'version=["\']([^"\']+)["\']', content)
    if not version_match:
        raise ValueError("Could not find version in setup.py")
    
    current_version = version_match.group(1)
    major, minor, patch = map(int, current_version.split('.'))
    
    # Calculate new version
    if version_type == 'major':
        new_version = f"{major + 1}.0.0"
    elif version_type == 'minor':
        new_version = f"{major}.{minor + 1}.0"
    elif version_type == 'patch':
        new_version = f"{major}.{minor}.{patch + 1}"
    else:
        raise ValueError("Invalid version type")
    
    print(f"Bumping version from {current_version} to {new_version}")
    
    # Update files
    files_to_update = [
        "setup.py",
        "src/nginx_security_monitor/__init__.py",
        "pyproject.toml",
        "docs/conf.py"
    ]
    
    for file_path in files_to_update:
        if Path(file_path).exists():
            content = Path(file_path).read_text()
            content = re.sub(
                rf'version\s*=\s*["\']?{re.escape(current_version)}["\']?',
                f'version = "{new_version}"',
                content
            )
            Path(file_path).write_text(content)
            print(f"Updated {file_path}")
    
    return new_version

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python bump_version.py [major|minor|patch]")
        sys.exit(1)
    
    version_type = sys.argv[1]
    new_version = bump_version(version_type)
    
    # Commit version bump
    subprocess.run(["git", "add", "-A"])
    subprocess.run(["git", "commit", "-m", f"Bump version to {new_version}"])
    
    print(f"Version bumped to {new_version}")
```

### 2. Changelog Generation

```bash
#!/bin/bash
# scripts/generate_changelog.py

#!/usr/bin/env python3
import subprocess
import re
from datetime import datetime
from pathlib import Path

def get_git_commits_since_tag(tag):
    """Get commits since last tag"""
    try:
        result = subprocess.run([
            "git", "log", f"{tag}..HEAD", 
            "--pretty=format:%H|%s|%an|%ad", 
            "--date=short"
        ], capture_output=True, text=True, check=True)
        
        commits = []
        for line in result.stdout.strip().split('\n'):
            if line:
                hash_val, subject, author, date = line.split('|', 3)
                commits.append({
                    'hash': hash_val,
                    'subject': subject,
                    'author': author,
                    'date': date
                })
        return commits
    except subprocess.CalledProcessError:
        return []

def categorize_commits(commits):
    """Categorize commits by type"""
    categories = {
        'Features': [],
        'Bug Fixes': [],
        'Performance': [],
        'Documentation': [],
        'Security': [],
        'Dependencies': [],
        'Other': []
    }
    
    patterns = {
        'Features': [r'^feat', r'^add', r'^implement'],
        'Bug Fixes': [r'^fix', r'^bug', r'^resolve'],
        'Performance': [r'^perf', r'^optimize', r'^improve'],
        'Documentation': [r'^docs?', r'^readme', r'^changelog'],
        'Security': [r'^security', r'^sec', r'^cve'],
        'Dependencies': [r'^deps?', r'^bump', r'^update.*dependency']
    }
    
    for commit in commits:
        subject = commit['subject'].lower()
        categorized = False
        
        for category, category_patterns in patterns.items():
            for pattern in category_patterns:
                if re.search(pattern, subject):
                    categories[category].append(commit)
                    categorized = True
                    break
            if categorized:
                break
        
        if not categorized:
            categories['Other'].append(commit)
    
    return categories

def generate_changelog_entry(version, categories):
    """Generate changelog entry"""
    today = datetime.now().strftime('%Y-%m-%d')
    
    changelog = f"\n## [{version}] - {today}\n\n"
    
    for category, commits in categories.items():
        if commits:
            changelog += f"### {category}\n\n"
            for commit in commits:
                # Remove conventional commit prefixes
                subject = re.sub(r'^(feat|fix|docs?|perf|security|deps?)(\([^)]+\))?: ', '', commit['subject'])
                changelog += f"- {subject} ({commit['hash'][:8]})\n"
            changelog += "\n"
    
    return changelog

def main():
    # Get last tag
    try:
        result = subprocess.run([
            "git", "describe", "--tags", "--abbrev=0"
        ], capture_output=True, text=True, check=True)
        last_tag = result.stdout.strip()
    except subprocess.CalledProcessError:
        last_tag = None
    
    if not last_tag:
        print("No previous tags found")
        return
    
    # Get version from command line or calculate
    import sys
    if len(sys.argv) > 1:
        version = sys.argv[1]
    else:
        print("Please provide version number")
        return
    
    # Get commits since last tag
    commits = get_git_commits_since_tag(last_tag)
    
    if not commits:
        print("No commits since last tag")
        return
    
    # Categorize commits
    categories = categorize_commits(commits)
    
    # Generate changelog entry
    changelog_entry = generate_changelog_entry(version, categories)
    
    # Prepend to CHANGELOG.md
    changelog_file = Path("CHANGELOG.md")
    if changelog_file.exists():
        existing_content = changelog_file.read_text()
        new_content = changelog_entry + existing_content
    else:
        new_content = f"# Changelog\n\nAll notable changes to this project will be documented in this file.\n{changelog_entry}"
    
    changelog_file.write_text(new_content)
    print(f"Changelog updated for version {version}")
    print(changelog_entry)

if __name__ == "__main__":
    main()
```

## Release Execution

### 1. Automated Release Pipeline

```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
          
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -r dev-requirements.txt
          
      - name: Run tests
        run: |
          python -m pytest tests/ -v --cov=src/nginx_security_monitor
          
      - name: Security scan
        run: |
          bandit -r src/
          safety check
          
      - name: Upload coverage
        uses: codecov/codecov-action@v3

  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
          
      - name: Build package
        run: |
          pip install build
          python -m build
          
      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        with:
          name: dist
          path: dist/

  docker:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2
        
      - name: Login to DockerHub
        uses: docker/login-action@v2
        with:
          username: <DOCKERHUB_USERNAME>
          password: <DOCKERHUB_TOKEN>
          
      - name: Extract version
        id: extract_version
        run: echo "VERSION=${GITHUB_REF#refs/tags/v}" >> $GITHUB_OUTPUT
        
      - name: Build and push
        uses: docker/build-push-action@v4
        with:
          context: .
          push: true
          tags: |
            nginx-security-monitor/nsm:<VERSION>
            nginx-security-monitor/nsm:latest
          cache-from: type=gha
          cache-to: type=gha,mode=max

  release:
    needs: [test, build, docker]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
          
      - name: Download artifacts
        uses: actions/download-artifact@v3
        with:
          name: dist
          path: dist/
          
      - name: Extract version
        id: extract_version
        run: echo "VERSION=${GITHUB_REF#refs/tags/v}" >> $GITHUB_OUTPUT
        
      - name: Generate release notes
        run: |
          python scripts/generate_release_notes.py <VERSION> > release_notes.md
          
      - name: Create Release
        uses: actions/create-release@v1
        env:
          GITHUB_TOKEN: <GITHUB_TOKEN>
        with:
          tag_name: <TAG_NAME>
          release_name: Release <VERSION>
          body_path: release_notes.md
          draft: false
          prerelease: false
          
      - name: Upload Release Assets
        run: |
          for file in dist/*; do
            gh release upload <TAG_NAME> "$file"
          done
        env:
          GITHUB_TOKEN: <GITHUB_TOKEN>
          
      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
        with:
          password: <PYPI_API_TOKEN>
```

### 2. Manual Release Steps

```bash
#!/bin/bash
# scripts/release.sh - Manual release script

set -euo pipefail

VERSION="$1"
RELEASE_TYPE="$2"  # major, minor, patch, hotfix

if [ -z "$VERSION" ] || [ -z "$RELEASE_TYPE" ]; then
    echo "Usage: $0 <version> <release_type>"
    exit 1
fi

echo "Starting release process for version $VERSION ($RELEASE_TYPE)"

# Pre-flight checks
echo "Running pre-flight checks..."

# Check if working directory is clean
if ! git diff-index --quiet HEAD --; then
    echo "Error: Working directory is not clean"
    exit 1
fi

# Check if on main branch
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "main" ]; then
    echo "Error: Not on main branch (current: $CURRENT_BRANCH)"
    exit 1
fi

# Run tests
echo "Running tests..."
python -m pytest tests/ -v

# Security checks
echo "Running security checks..."
bandit -r src/
safety check

# Update version
echo "Updating version to $VERSION..."
python scripts/bump_version.py "$RELEASE_TYPE"

# Generate changelog
echo "Generating changelog..."
python scripts/generate_changelog.py "$VERSION"

# Build package
echo "Building package..."
python -m build

# Create git tag
echo "Creating git tag..."
git tag -a "v$VERSION" -m "Release version $VERSION"

# Push changes
echo "Pushing changes..."
git push origin main
git push origin "v$VERSION"

# Build Docker image
echo "Building Docker image..."
docker build -t "nginx-security-monitor:$VERSION" .
docker tag "nginx-security-monitor:$VERSION" "nginx-security-monitor:latest"

echo "Release $VERSION completed successfully!"
echo "Next steps:"
echo "1. Monitor the GitHub Actions pipeline"
echo "2. Verify Docker image deployment"
echo "3. Update documentation if needed"
echo "4. Send release announcement"
```

## Post-Release Activities

### 1. Release Validation

```bash
#!/bin/bash
# scripts/validate_release.sh

VERSION="$1"

echo "Validating release $VERSION..."

# Check GitHub release
echo "Checking GitHub release..."
curl -s "https://api.github.com/repos/AccessiTech/nginx-security-monitor/releases/tags/v$VERSION" | jq -r '.name'

# Check PyPI package
echo "Checking PyPI package..."
pip index versions nginx-security-monitor | grep "$VERSION"

# Check Docker image
echo "Checking Docker image..."
docker pull "nginx-security-monitor:$VERSION"
docker run --rm "nginx-security-monitor:$VERSION" --version

# Test installation
echo "Testing installation..."
pip install "nginx-security-monitor==$VERSION"
python -c "import nginx_security_monitor; print(nginx_security_monitor.__version__)"

echo "Release validation completed"
```

### 2. Release Communication

```python
# scripts/send_release_announcement.py
#!/usr/bin/env python3

import requests
import json
from pathlib import Path

def send_slack_announcement(version, changelog_excerpt):
    """Send release announcement to Slack"""
    webhook_url = "YOUR_SLACK_WEBHOOK_URL"
    
    message = {
        "text": f"🚀 Nginx Security Monitor {version} Released!",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚀 NSM {version} Released!"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"A new version of Nginx Security Monitor is now available!\n\n*What's New:*\n{changelog_excerpt}"
                }
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "View Release Notes"
                        },
                        "url": f"https://github.com/AccessiTech/nginx-security-monitor/releases/tag/v{version}" 
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "Download"
                        },
                        "url": f"https://pypi.org/project/nginx-security-monitor/{version}/"
                    }
                ]
            }
        ]
    }
    
    response = requests.post(webhook_url, json=message)
    return response.status_code == 200

def send_email_announcement(version, changelog_excerpt):
    """Send release announcement via email"""
    # Implementation depends on your email service
    pass

def main():
    import sys
    if len(sys.argv) != 2:
        print("Usage: python send_release_announcement.py <version>")
        sys.exit(1)
    
    version = sys.argv[1]
    
    # Extract changelog excerpt
    changelog = Path("CHANGELOG.md").read_text()
    # Extract the latest release section
    lines = changelog.split('\n')
    excerpt_lines = []
    in_current_release = False
    
    for line in lines:
        if line.startswith(f"## [{version}]"):
            in_current_release = True
            continue
        elif line.startswith("## [") and in_current_release:
            break
        elif in_current_release and line.strip():
            excerpt_lines.append(line)
    
    changelog_excerpt = '\n'.join(excerpt_lines[:10])  # First 10 lines
    
    # Send announcements
    if send_slack_announcement(version, changelog_excerpt):
        print("✅ Slack announcement sent")
    else:
        print("❌ Failed to send Slack announcement")

if __name__ == "__main__":
    main()
```

## Release Checklist Template

```markdown
# Release Checklist: Version X.Y.Z

## Pre-Release
- [ ] All features implemented and tested
- [ ] Code review completed
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped in all files
- [ ] Tests passing (unit, integration, security)
- [ ] Dependencies updated and scanned
- [ ] Breaking changes documented

## Release Execution
- [ ] Git tag created and pushed
- [ ] GitHub Actions pipeline triggered
- [ ] Docker image built and pushed
- [ ] PyPI package published
- [ ] GitHub release created
- [ ] Release notes published

## Post-Release
- [ ] Release validation completed
- [ ] Docker image tested
- [ ] PyPI package tested
- [ ] Documentation site updated
- [ ] Release announcement sent
- [ ] Monitoring alerts configured
- [ ] Support team notified

## Follow-up (within 48 hours)
- [ ] Monitor for issues or bug reports
- [ ] Check download/adoption metrics
- [ ] Update project roadmap
- [ ] Plan next release cycle

---
**Release Manager:** [Name]
**Release Date:** [Date]
**Release Type:** [Major/Minor/Patch/Hotfix]
```

## Hotfix Process

### Emergency Hotfix Procedure

```bash
#!/bin/bash
# scripts/hotfix.sh - Emergency hotfix procedure

set -euo pipefail

HOTFIX_VERSION="$1"
DESCRIPTION="$2"

if [ -z "$HOTFIX_VERSION" ] || [ -z "$DESCRIPTION" ]; then
    echo "Usage: $0 <hotfix_version> <description>"
    echo "Example: $0 1.2.3-hotfix.1 'Fix critical security vulnerability'"
    exit 1
fi

echo "Starting emergency hotfix: $HOTFIX_VERSION"
echo "Description: $DESCRIPTION"

# Create hotfix branch from latest release tag
LATEST_TAG=$(git describe --tags --abbrev=0)
git checkout -b "hotfix/$HOTFIX_VERSION" "$LATEST_TAG"

echo "Created hotfix branch from $LATEST_TAG"
echo "Apply your fixes now and commit them."
echo "Press Enter when ready to continue with release..."
read

# Quick validation
echo "Running critical tests..."
python -m pytest tests/critical/ -v

# Update version
echo "Updating version to $HOTFIX_VERSION..."
sed -i "s/version = .*/version = \"$HOTFIX_VERSION\"/" setup.py

# Commit hotfix
git add -A
git commit -m "Hotfix $HOTFIX_VERSION: $DESCRIPTION"

# Create tag
git tag -a "v$HOTFIX_VERSION" -m "Hotfix: $DESCRIPTION"

# Push hotfix
git push origin "hotfix/$HOTFIX_VERSION"
git push origin "v$HOTFIX_VERSION"

# Merge back to main
git checkout main
git merge --no-ff "hotfix/$HOTFIX_VERSION"
git push origin main

echo "Hotfix $HOTFIX_VERSION completed"
echo "Monitor the automated pipeline for deployment"
```

______________________________________________________________________

**Related Documentation:**

- [Contributing Guidelines](../CONTRIBUTING.md)
- [Code Review Guidelines](code-review.md)
- [Testing Guide](../TESTING.md)
- [Deployment Guide](../deployment/README.md)
