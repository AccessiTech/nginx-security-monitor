# Architecture Decision Records (ADRs)

This directory contains Architecture Decision Records (ADRs) for Nginx Security Monitor. ADRs document important architectural decisions, their context, and rationale.

## What are ADRs?

Architecture Decision Records are documents that capture important architectural decisions made during the development of a system, along with their context and consequences.

## ADR Format

We use the following template for all ADRs:

```markdown
# ADR-NNNN: Title

## Status
[Proposed | Accepted | Rejected | Superseded | Deprecated]

## Context
The issue motivating this decision, and any context that influences or constrains the decision.

## Decision
The change that we're proposing or have agreed to implement.

## Consequences
What becomes easier or more difficult to do and any risks introduced by the change that will need to be mitigated.

## Implementation
Specific steps or considerations for implementing this decision.

## Related Decisions
References to related ADRs or external documents.
```

## ADR Index

| Number                                         | Title                                 | Status   | Date       |
| ---------------------------------------------- | ------------------------------------- | -------- | ---------- |
| [0001](0001-use-python-for-implementation.md)  | Use Python for Implementation         | Accepted | 2024-01-15 |
| [0002](0002-pattern-based-detection-engine.md) | Pattern-Based Detection Engine        | Accepted | 2024-01-20 |
| [0003](0003-plugin-architecture.md)            | Plugin Architecture for Extensibility | Accepted | 2024-02-01 |
| [0004](0004-encryption-at-rest.md)             | Encryption at Rest for Sensitive Data | Accepted | 2024-02-15 |
| [0005](0005-api-versioning-strategy.md)        | API Versioning Strategy               | Accepted | 2024-03-01 |
| [0006](0006-log-processing-pipeline.md)        | Asynchronous Log Processing Pipeline  | Accepted | 2024-03-15 |
| [0007](0007-integration-framework.md)          | Standardized Integration Framework    | Accepted | 2024-04-01 |
| [0008](0008-configuration-management.md)       | Hierarchical Configuration Management | Accepted | 2024-04-15 |
| [0009](0009-monitoring-and-observability.md)   | Monitoring and Observability Strategy | Accepted | 2024-05-01 |
| [0010](0010-security-model.md)                 | Security Model and Threat Surface     | Accepted | 2024-05-15 |

## Creating New ADRs

### 1. Use the ADR Template

```bash
# Create new ADR
cp docs/architecture/decisions/template.md docs/architecture/decisions/NNNN-your-decision-title.md

# Edit the new ADR
vim docs/architecture/decisions/NNNN-your-decision-title.md
```

### 2. ADR Numbering

- Use sequential numbering: 0001, 0002, 0003, etc.
- Check the index above for the next available number
- Pad with zeros to maintain consistent formatting

### 3. ADR Lifecycle

1. **Proposed**: Initial draft, under discussion
1. **Accepted**: Decision has been made and approved
1. **Rejected**: Decision was considered but not adopted
1. **Superseded**: Replaced by a newer decision
1. **Deprecated**: No longer relevant or recommended

### 4. Review Process

1. Create ADR in "Proposed" status
1. Share with team for review and discussion
1. Update based on feedback
1. Change status to "Accepted" when approved
1. Update the index table

## Tools and Automation

### ADR Generator Script

```python
#!/usr/bin/env python3
# scripts/create_adr.py

import os
import sys
import datetime
from pathlib import Path

class ADRGenerator:
    def __init__(self, adr_dir="docs/architecture/decisions"):
        self.adr_dir = Path(adr_dir)
        self.template_file = self.adr_dir / "template.md"
        
    def get_next_number(self):
        """Get the next ADR number"""
        existing_adrs = list(self.adr_dir.glob("[0-9][0-9][0-9][0-9]-*.md"))
        if not existing_adrs:
            return 1
        
        numbers = []
        for adr_file in existing_adrs:
            try:
                number = int(adr_file.name[:4])
                numbers.append(number)
            except ValueError:
                continue
        
        return max(numbers) + 1 if numbers else 1
    
    def create_adr(self, title, context="", decision="", author=""):
        """Create a new ADR"""
        number = self.get_next_number()
        filename = f"{number:04d}-{self.slugify(title)}.md"
        filepath = self.adr_dir / filename
        
        template = self.load_template()
        content = template.format(
            number=f"{number:04d}",
            title=title,
            date=datetime.date.today().isoformat(),
            author=author or "Unknown",
            context=context or "<!-- Describe the context and problem statement -->",
            decision=decision or "<!-- Describe the decision and rationale -->"
        )
        
        with open(filepath, 'w') as f:
            f.write(content)
        
        print(f"Created ADR: {filepath}")
        print(f"Please edit the file and update the index in README.md")
        
        return filepath
    
    def load_template(self):
        """Load ADR template"""
        if self.template_file.exists():
            return self.template_file.read_text()
        else:
            return self.get_default_template()
    
    def get_default_template(self):
        """Get default ADR template"""
        return """# ADR-{number}: {title}

## Status
Proposed

## Date
{date}

## Author
{author}

## Context
{context}

## Decision
{decision}

## Consequences
<!-- What becomes easier or more difficult to do? -->

## Implementation
<!-- Steps for implementing this decision -->

## Related Decisions
<!-- References to related ADRs -->

## Notes
<!-- Additional notes or considerations -->
"""
    
    def slugify(self, title):
        """Convert title to filename-friendly slug"""
        slug = title.lower()
        slug = ''.join(c if c.isalnum() or c in '-_' else '-' for c in slug)
        slug = '-'.join(filter(None, slug.split('-')))  # Remove empty parts
        return slug[:50]  # Limit length

def main():
    if len(sys.argv) < 2:
        print("Usage: python create_adr.py 'ADR Title' [context] [decision] [author]")
        sys.exit(1)
    
    title = sys.argv[1]
    context = sys.argv[2] if len(sys.argv) > 2 else ""
    decision = sys.argv[3] if len(sys.argv) > 3 else ""
    author = sys.argv[4] if len(sys.argv) > 4 else ""
    
    generator = ADRGenerator()
    filepath = generator.create_adr(title, context, decision, author)
    
    # Open in editor if available
    if os.environ.get('EDITOR'):
        os.system(f"{os.environ['EDITOR']} {filepath}")

if __name__ == "__main__":
    main()
```

### ADR Status Tracker

```python
#!/usr/bin/env python3
# scripts/adr_status.py

import re
import json
from pathlib import Path
from typing import Dict, List
import datetime

class ADRTracker:
    def __init__(self, adr_dir="docs/architecture/decisions"):
        self.adr_dir = Path(adr_dir)
    
    def scan_adrs(self) -> List[Dict]:
        """Scan all ADRs and extract metadata"""
        adrs = []
        
        for adr_file in sorted(self.adr_dir.glob("[0-9][0-9][0-9][0-9]-*.md")):
            metadata = self.extract_metadata(adr_file)
            if metadata:
                adrs.append(metadata)
        
        return adrs
    
    def extract_metadata(self, adr_file: Path) -> Dict:
        """Extract metadata from ADR file"""
        try:
            content = adr_file.read_text()
            
            # Extract title
            title_match = re.search(r'^# ADR-(\d+): (.+)$', content, re.MULTILINE)
            if not title_match:
                return None
            
            number = title_match.group(1)
            title = title_match.group(2)
            
            # Extract status
            status_match = re.search(r'^## Status\s*\n(.+)$', content, re.MULTILINE)
            status = status_match.group(1).strip() if status_match else "Unknown"
            
            # Extract date
            date_match = re.search(r'^## Date\s*\n(.+)$', content, re.MULTILINE)
            date = date_match.group(1).strip() if date_match else "Unknown"
            
            # Extract author
            author_match = re.search(r'^## Author\s*\n(.+)$', content, re.MULTILINE)
            author = author_match.group(1).strip() if author_match else "Unknown"
            
            return {
                "number": number,
                "title": title,
                "status": status,
                "date": date,
                "author": author,
                "filename": adr_file.name,
                "filepath": str(adr_file)
            }
        
        except Exception as e:
            print(f"Error processing {adr_file}: {e}")
            return None
    
    def generate_index(self) -> str:
        """Generate ADR index table"""
        adrs = self.scan_adrs()
        
        index = "| Number | Title | Status | Date |\n"
        index += "|--------|-------|--------|----- |\n"
        
        for adr in adrs:
            link = f"[{adr['number']}]({adr['filename']})"
            index += f"| {link} | {adr['title']} | {adr['status']} | {adr['date']} |\n"
        
        return index
    
    def generate_status_report(self) -> Dict:
        """Generate status report"""
        adrs = self.scan_adrs()
        
        status_counts = {}
        for adr in adrs:
            status = adr['status']
            status_counts[status] = status_counts.get(status, 0) + 1
        
        recent_adrs = [adr for adr in adrs 
                      if self.is_recent(adr['date'], days=90)]
        
        return {
            "total_adrs": len(adrs),
            "status_counts": status_counts,
            "recent_adrs": len(recent_adrs),
            "last_updated": datetime.datetime.now().isoformat()
        }
    
    def is_recent(self, date_str: str, days: int = 90) -> bool:
        """Check if date is within the last N days"""
        try:
            adr_date = datetime.datetime.fromisoformat(date_str)
            cutoff = datetime.datetime.now() - datetime.timedelta(days=days)
            return adr_date >= cutoff
        except:
            return False
    
    def validate_adrs(self) -> List[Dict]:
        """Validate ADR format and content"""
        adrs = self.scan_adrs()
        issues = []
        
        for adr in adrs:
            adr_issues = []
            
            # Check required sections
            content = Path(adr['filepath']).read_text()
            required_sections = ["Status", "Context", "Decision", "Consequences"]
            
            for section in required_sections:
                if f"## {section}" not in content:
                    adr_issues.append(f"Missing required section: {section}")
            
            # Check status validity
            valid_statuses = ["Proposed", "Accepted", "Rejected", "Superseded", "Deprecated"]
            if adr['status'] not in valid_statuses:
                adr_issues.append(f"Invalid status: {adr['status']}")
            
            # Check for placeholder content
            if "<!-- " in content:
                adr_issues.append("Contains placeholder content")
            
            if adr_issues:
                issues.append({
                    "adr": adr['filename'],
                    "issues": adr_issues
                })
        
        return issues

def main():
    import sys
    
    tracker = ADRTracker()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "index":
            print(tracker.generate_index())
        elif command == "status":
            report = tracker.generate_status_report()
            print(json.dumps(report, indent=2))
        elif command == "validate":
            issues = tracker.validate_adrs()
            if issues:
                print("ADR Validation Issues:")
                for issue in issues:
                    print(f"\n{issue['adr']}:")
                    for problem in issue['issues']:
                        print(f"  - {problem}")
            else:
                print("All ADRs are valid!")
        else:
            print("Usage: python adr_status.py [index|status|validate]")
    else:
        # Default: show status
        report = tracker.generate_status_report()
        print(f"Total ADRs: {report['total_adrs']}")
        print("Status breakdown:")
        for status, count in report['status_counts'].items():
            print(f"  {status}: {count}")

if __name__ == "__main__":
    main()
```

## Example ADRs

Let me create a few sample ADRs to demonstrate the format:

\<function_calls>
<invoke name="create_file">
<parameter name="content"># ADR-0001: Use Python for Implementation

## Status

Accepted

## Date

2024-01-15

## Author

Development Team

## Context

We need to choose a programming language for implementing the Nginx Security Monitor. The system needs to:

- Process log files efficiently
- Handle regex pattern matching at scale
- Integrate with various security tools
- Be maintainable by a diverse team
- Support rapid prototyping and iteration

Key considerations:

- **Performance**: Need to process thousands of log entries per second
- **Ecosystem**: Rich libraries for security, networking, and data processing
- **Team expertise**: Current team has strong Python experience
- **Integration**: Many security tools provide Python APIs
- **Deployment**: Must be easily deployable in various environments

Alternative options considered:

1. **Go**: High performance, good concurrency, smaller ecosystem
1. **Rust**: Excellent performance, memory safety, steeper learning curve
1. **Java**: Mature ecosystem, verbose syntax, higher resource usage
1. **Python**: Rich ecosystem, readable code, potentially slower performance

## Decision

We will use **Python 3.8+** as the primary implementation language for Nginx Security Monitor.

Rationale:

- **Rich Security Ecosystem**: Extensive libraries for security analysis (regex, cryptography, network protocols)
- **Integration Capabilities**: Native support for major security tools (fail2ban, OSSEC, Suricata)
- **Team Productivity**: Faster development cycles, readable code, extensive documentation
- **Performance Adequacy**: With proper optimization (compiled regex, asyncio), Python can meet our performance requirements
- **Deployment Flexibility**: Easy containerization, package management, and cross-platform support

## Consequences

### Positive

- **Faster Development**: Rapid prototyping and iteration
- **Rich Libraries**: Access to mature security and data processing libraries
- **Team Efficiency**: Leverages existing team expertise
- **Integration Ease**: Simplified integration with security tools
- **Maintainability**: Clear, readable code that's easy to maintain

### Negative

- **Performance Overhead**: May require optimization for high-throughput scenarios
- **Dependency Management**: Need careful management of dependencies
- **Runtime Requirements**: Requires Python runtime in deployment environments

### Neutral

- **Learning Curve**: Minimal for current team
- **Ecosystem Maturity**: Well-established but evolving

## Implementation

### Development Environment

- Python 3.8+ (for typing support and performance improvements)
- Virtual environments for dependency isolation
- pip-tools for reproducible dependency management

### Performance Optimization

- Use compiled regex patterns for threat detection
- Implement asyncio for concurrent log processing
- Profile and optimize critical paths
- Consider Cython for performance-critical components

### Code Quality

- Use type hints throughout the codebase
- Implement comprehensive test suite
- Use linting tools (flake8, black, mypy)
- Follow PEP 8 style guidelines

### Deployment

- Container-first deployment strategy
- Minimal base images for security
- Multi-stage builds for smaller production images

## Related Decisions

- ADR-0002: Pattern-Based Detection Engine
- ADR-0006: Asynchronous Log Processing Pipeline

## Notes

- Performance will be continuously monitored and optimized
- Consider alternative languages for specific performance-critical components if needed
- Regular evaluation of the decision as requirements evolve
