______________________________________________________________________

version: 1.0.0
last_updated: 2025-07-20
changelog:

- version: 1.0.0
  date: 2025-07-20
  changes:
  - Initial style guide creation
    maintainers:
- nginx-security-team
  review_status: current
  applies_to_versions: '>=1.0.0'

______________________________________________________________________

# 📝 Documentation Style Guide

This style guide provides guidelines for writing and maintaining documentation for the NGINX Security Monitor project.

## General Principles

1. **Clarity First**

   - Write in clear, concise language
   - One idea per sentence
   - Use active voice
   - Avoid jargon unless necessary
   - Define technical terms on first use

1. **Consistency**

   - Use consistent terminology throughout
   - Maintain consistent formatting
   - Follow established patterns
   - Use standard file naming conventions

## File Structure

### Metadata Header

```markdown
---
version: 1.0.0
last_updated: YYYY-MM-DD
changelog:
  - version: 1.0.0
    date: YYYY-MM-DD
    changes:
      - Change description
maintainers:
  - username
review_status: current|needs_review|outdated
applies_to_versions: ">=X.Y.Z"
---
```

### Document Structure

```markdown
# Title (Level 1)

Brief description (1-2 sentences)

## Section (Level 2)

### Subsection (Level 3)

#### Detail (Level 4)
```

## Formatting Conventions

### Code Blocks

- Use triple backticks with language specification
- Include description before code blocks
- Keep code examples concise and focused

```python
# Good example
def validate_config():
    """Validate the configuration file."""
    return True
```

### Links

- Use descriptive link text
- Prefer relative links for internal documentation
- Include link titles for external resources

### Lists

- Use hyphen (-) for unordered lists
- Use numbers (1.) for ordered lists
- Maintain consistent indentation (2 spaces)
- Capitalize first word of each item
- End each item with appropriate punctuation

## File Naming

- Use uppercase for root-level documentation: `README.md`, `CONTRIBUTING.md`
- Use lowercase with hyphens for other files: `user-guide.md`, `api-reference.md`
- Use descriptive, purpose-indicating names

## Writing Style

### Voice and Tone

- Use active voice
- Be direct and concise
- Maintain a professional, helpful tone
- Write in present tense
- Use second person ("you") for instructions

### Code References

- Use backticks for inline code: \`variable_name\`
- Use proper case for language keywords
- Include language identifier in code blocks
- Document return values and exceptions

### Common Terms

- NGINX Security Monitor (not "the monitor" or "NSM")
- Configuration (not "config" or "conf")
- Documentation (not "docs" or "doc")
- Implementation (not "impl")

## Images and Diagrams

### Screenshots

- Include descriptive alt text
- Use consistent resolution
- Highlight relevant areas
- Update when UI changes

### Diagrams

- Use consistent styling
- Include legend when necessary
- Provide text description
- Save in both SVG and PNG formats

## Versioning

### Version Numbers

- Follow semantic versioning
- Include in metadata header
- Reference specific versions in examples
- Document version-specific features

### Compatibility Notes

- Clearly mark deprecated features
- Include version ranges
- Note breaking changes
- Provide migration steps

## Examples

### Good Example

````markdown
## Installing the Monitor

To install NGINX Security Monitor:

1. Clone the repository:
   ```bash
   git clone https://github.com/AccessiTech/nginx-security-monitor.git
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

````

### Bad Example

```markdown
## Installation

clone repo
run pip install
```

## Review Process

1. **Self-Review Checklist**

   - [ ] Correct metadata header
   - [ ] Proper formatting
   - [ ] No spelling errors
   - [ ] Links working
   - [ ] Code examples tested
   - [ ] Images have alt text

1. **Peer Review Guidelines**

   - Technical accuracy
   - Clarity and completeness
   - Style guide compliance
   - Cross-reference verification

## Tools and Automation

### Recommended Tools

- markdownlint for markdown validation
- Vale for style checking
- Prettier for formatting
- Local spell checker
- Link checker

### Pre-commit Hooks

- Markdown lint
- Spell check
- Link validation
- Format check

## Questions?

If you have questions about the style guide:

1. Check existing documentation
1. Ask in the #documentation channel
1. Create an issue with the "documentation" label
1. Tag maintainers for clarification
