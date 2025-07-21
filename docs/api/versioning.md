# API Versioning Guide

This guide covers the API versioning strategy, compatibility management, and migration
procedures for Nginx Security Monitor APIs.

## Versioning Strategy

Nginx Security Monitor follows **Semantic Versioning (SemVer)** for API compatibility:

- **Major Version (X.0.0)**: Breaking changes, incompatible API changes
- **Minor Version (x.Y.0)**: New features, backwards-compatible additions
- **Patch Version (x.y.Z)**: Bug fixes, backwards-compatible fixes

### API Version Format

```text
v{MAJOR}.{MINOR}[.{PATCH}]
```

Examples:

- `v1.0` - Major version 1, minor version 0
- `v1.2` - Major version 1, minor version 2
- `v2.0` - Major version 2 (breaking changes from v1.x)

## API Endpoints and Versioning

### URL Versioning (Primary Method)

```http
# Current stable API
GET /api/v1/health
GET /api/v1/config
GET /api/v1/patterns
GET /api/v1/alerts
GET /api/v1/integrations

# Beta/experimental API
GET /api/v2/health
GET /api/v2/config
GET /api/v2/patterns
```

### Header Versioning (Alternative)

```http
GET /api/health
Accept: application/json; version=1.0
API-Version: 1.0
```

### Content Negotiation

```http
# Request specific version
GET /api/v1/config
Accept: application/vnd.nsm.v1+json

# Latest version
GET /api/config
Accept: application/json
```

## Compatibility Matrix

### Current API Versions

| API Version | Status | Released   | End of Life | Breaking Changes |
| ----------- | ------ | ---------- | ----------- | ---------------- |
| v1.0        | Stable | 2024-01-15 | 2026-01-15  | None             |
| v1.1        | Stable | 2024-06-01 | 2026-06-01  | None             |
| v1.2        | Stable | 2024-12-01 | 2026-12-01  | None             |
| v2.0        | Beta   | 2025-03-01 | TBD         | Multiple         |

### Version Support Policy

- **Stable versions**: Supported for 2 years from release
- **Beta versions**: No support guarantees, may change without notice
- **Deprecated versions**: 6-month deprecation notice before removal
- **Security updates**: Applied to all supported versions

## API Evolution Examples

### Adding New Fields (Minor Version)

**v1.0 Response:**

```json
{
  "id": "pattern_001",
  "name": "SQL Injection",
  "pattern": "(?i)(union.*select|select.*from)",
  "severity": "high"
}
```

**v1.1 Response (Backwards Compatible):**

```json
{
  "id": "pattern_001",
  "name": "SQL Injection",
  "pattern": "(?i)(union.*select|select.*from)",
  "severity": "high",
  "category": "injection",
  "confidence": 0.95,
  "last_updated": "2024-06-01T10:00:00Z"
}
```

### Breaking Changes (Major Version)

**v1.x Request:**

```json
{
  "pattern": "(?i)(union.*select)",
  "severity": "high",
  "enabled": true
}
```

**v2.0 Request (Breaking Changes):**

```json
{
  "detection_rule": {
    "regex_pattern": "(?i)(union.*select)",
    "risk_level": "critical",
    "active": true,
    "metadata": {
      "category": "sql_injection",
      "confidence_threshold": 0.8
    }
  }
}
```

## Automated Version Checking

### Version Compatibility Script

```python
#!/usr/bin/env python3
# scripts/check_api_compatibility.py

import requests
import json
import sys
from typing import Dict, List, Tuple
from packaging import version

class APICompatibilityChecker:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.supported_versions = ['v1.0', 'v1.1', 'v1.2', 'v2.0']
    
    def get_available_versions(self) -> List[str]:
        """Get list of available API versions"""
        try:
            response = requests.get(f"{self.base_url}/api/versions")
            if response.status_code == 200:
                return response.json().get('versions', [])
            else:
                # Fallback: probe each version
                available = []
                for ver in self.supported_versions:
                    if self.probe_version(ver):
                        available.append(ver)
                return available
        except Exception as e:
            print(f"Error checking versions: {e}")
            return []
    
    def probe_version(self, version: str) -> bool:
        """Check if a specific version is available"""
        try:
            response = requests.get(f"{self.base_url}/api/{version}/health")
            return response.status_code == 200
        except:
            return False
    
    def check_endpoint_compatibility(self, endpoint: str, 
                                   from_version: str, 
                                   to_version: str) -> Dict:
        """Check compatibility between two versions for an endpoint"""
        
        results = {
            'compatible': True,
            'breaking_changes': [],
            'new_features': [],
            'deprecated_fields': []
        }
        
        # Get schema for both versions
        from_schema = self.get_endpoint_schema(endpoint, from_version)
        to_schema = self.get_endpoint_schema(endpoint, to_version)
        
        if not from_schema or not to_schema:
            results['compatible'] = False
            results['breaking_changes'].append("Unable to retrieve schema")
            return results
        
        # Check for breaking changes
        results.update(self.compare_schemas(from_schema, to_schema))
        
        return results
    
    def get_endpoint_schema(self, endpoint: str, version: str) -> Dict:
        """Get OpenAPI schema for endpoint"""
        try:
            response = requests.get(f"{self.base_url}/api/{version}/schema/{endpoint}")
            if response.status_code == 200:
                return response.json()
        except:
            pass
        
        # Fallback: make actual request and infer schema
        try:
            response = requests.get(f"{self.base_url}/api/{version}/{endpoint}")
            if response.status_code == 200:
                return self.infer_schema(response.json())
        except:
            pass
        
        return {}
    
    def compare_schemas(self, from_schema: Dict, to_schema: Dict) -> Dict:
        """Compare two schemas for compatibility"""
        results = {
            'compatible': True,
            'breaking_changes': [],
            'new_features': [],
            'deprecated_fields': []
        }
        
        # Check for removed fields (breaking change)
        from_fields = set(self.extract_fields(from_schema))
        to_fields = set(self.extract_fields(to_schema))
        
        removed_fields = from_fields - to_fields
        added_fields = to_fields - from_fields
        
        if removed_fields:
            results['compatible'] = False
            results['breaking_changes'].extend([
                f"Removed field: {field}" for field in removed_fields
            ])
        
        if added_fields:
            results['new_features'].extend([
                f"Added field: {field}" for field in added_fields
            ])
        
        return results
    
    def extract_fields(self, schema: Dict, prefix: str = "") -> List[str]:
        """Extract field names from schema"""
        fields = []
        if isinstance(schema, dict):
            for key, value in schema.items():
                field_name = f"{prefix}.{key}" if prefix else key
                fields.append(field_name)
                if isinstance(value, dict):
                    fields.extend(self.extract_fields(value, field_name))
        return fields
    
    def infer_schema(self, data: Dict) -> Dict:
        """Infer schema from response data"""
        if isinstance(data, dict):
            return {key: type(value).__name__ for key, value in data.items()}
        return {}

def main():
    if len(sys.argv) != 4:
        print("Usage: python check_api_compatibility.py <base_url> <from_version> <to_version>")
        sys.exit(1)
    
    base_url, from_version, to_version = sys.argv[1:4]
    
    checker = APICompatibilityChecker(base_url)
    
    # Check main endpoints
    endpoints = ['health', 'config', 'patterns', 'alerts', 'integrations']
    
    print(f"Checking compatibility: {from_version} → {to_version}")
    print("=" * 50)
    
    overall_compatible = True
    
    for endpoint in endpoints:
        print(f"\nEndpoint: /{endpoint}")
        result = checker.check_endpoint_compatibility(endpoint, from_version, to_version)
        
        if result['compatible']:
            print("  ✅ Compatible")
        else:
            print("  ❌ Breaking changes detected")
            overall_compatible = False
        
        if result['breaking_changes']:
            print("  Breaking changes:")
            for change in result['breaking_changes']:
                print(f"    - {change}")
        
        if result['new_features']:
            print("  New features:")
            for feature in result['new_features']:
                print(f"    + {feature}")
    
    print("\n" + "=" * 50)
    if overall_compatible:
        print("✅ Migration should be safe")
    else:
        print("⚠️  Migration requires code changes")
    
    sys.exit(0 if overall_compatible else 1)

if __name__ == "__main__":
    main()
```

### Automated API Diff Generation

```python
#!/usr/bin/env python3
# scripts/generate_api_diff.py

import requests
import json
import sys
from deepdiff import DeepDiff
from typing import Dict, Any
import yaml

class APIDiffGenerator:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
    
    def get_api_spec(self, version: str) -> Dict[str, Any]:
        """Get OpenAPI specification for a version"""
        try:
            response = requests.get(f"{self.base_url}/api/{version}/openapi.json")
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"Error fetching API spec for {version}: {e}")
        return {}
    
    def generate_diff(self, from_version: str, to_version: str) -> Dict[str, Any]:
        """Generate detailed API diff between versions"""
        
        from_spec = self.get_api_spec(from_version)
        to_spec = self.get_api_spec(to_version)
        
        if not from_spec or not to_spec:
            return {"error": "Unable to fetch API specifications"}
        
        # Use DeepDiff to compare specifications
        diff = DeepDiff(from_spec, to_spec, ignore_order=True)
        
        # Process and categorize changes
        processed_diff = self.process_diff(diff)
        
        return {
            "from_version": from_version,
            "to_version": to_version,
            "summary": self.generate_summary(processed_diff),
            "changes": processed_diff,
            "migration_guide": self.generate_migration_guide(processed_diff)
        }
    
    def process_diff(self, diff: DeepDiff) -> Dict[str, Any]:
        """Process DeepDiff output into categorized changes"""
        
        changes = {
            "breaking_changes": [],
            "new_features": [],
            "deprecations": [],
            "bug_fixes": [],
            "improvements": []
        }
        
        # Process different types of changes
        if 'dictionary_item_removed' in diff:
            for item in diff['dictionary_item_removed']:
                if '/paths/' in str(item):
                    changes['breaking_changes'].append({
                        "type": "endpoint_removed",
                        "description": f"Endpoint removed: {item}",
                        "impact": "high"
                    })
                elif '/definitions/' in str(item) or '/components/' in str(item):
                    changes['breaking_changes'].append({
                        "type": "schema_removed",
                        "description": f"Schema removed: {item}",
                        "impact": "high"
                    })
        
        if 'dictionary_item_added' in diff:
            for item in diff['dictionary_item_added']:
                if '/paths/' in str(item):
                    changes['new_features'].append({
                        "type": "endpoint_added",
                        "description": f"New endpoint: {item}",
                        "impact": "none"
                    })
                elif '/definitions/' in str(item) or '/components/' in str(item):
                    changes['new_features'].append({
                        "type": "schema_added",
                        "description": f"New schema: {item}",
                        "impact": "none"
                    })
        
        if 'values_changed' in diff:
            for item, change in diff['values_changed'].items():
                changes['improvements'].append({
                    "type": "value_changed",
                    "description": f"Changed: {item}",
                    "from": change['old_value'],
                    "to": change['new_value'],
                    "impact": "low"
                })
        
        return changes
    
    def generate_summary(self, changes: Dict[str, Any]) -> Dict[str, int]:
        """Generate summary statistics"""
        return {
            "breaking_changes": len(changes['breaking_changes']),
            "new_features": len(changes['new_features']),
            "deprecations": len(changes['deprecations']),
            "total_changes": sum(len(changes[key]) for key in changes)
        }
    
    def generate_migration_guide(self, changes: Dict[str, Any]) -> Dict[str, Any]:
        """Generate migration guide based on changes"""
        
        guide = {
            "required_actions": [],
            "recommended_actions": [],
            "code_examples": []
        }
        
        # Required actions for breaking changes
        for change in changes['breaking_changes']:
            if change['type'] == 'endpoint_removed':
                guide['required_actions'].append({
                    "action": "Update API calls",
                    "description": f"Replace calls to removed endpoint: {change['description']}",
                    "urgency": "high"
                })
            elif change['type'] == 'schema_removed':
                guide['required_actions'].append({
                    "action": "Update data models",
                    "description": f"Update models for removed schema: {change['description']}",
                    "urgency": "high"
                })
        
        # Recommended actions for new features
        for change in changes['new_features']:
            if change['type'] == 'endpoint_added':
                guide['recommended_actions'].append({
                    "action": "Consider using new endpoint",
                    "description": f"New endpoint available: {change['description']}",
                    "benefit": "Enhanced functionality"
                })
        
        return guide
    
    def export_diff(self, diff_data: Dict[str, Any], format: str = 'json') -> str:
        """Export diff in specified format"""
        if format == 'json':
            return json.dumps(diff_data, indent=2)
        elif format == 'yaml':
            return yaml.dump(diff_data, default_flow_style=False)
        elif format == 'markdown':
            return self.format_as_markdown(diff_data)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def format_as_markdown(self, diff_data: Dict[str, Any]) -> str:
        """Format diff as Markdown"""
        md = f"# API Diff: {diff_data['from_version']} → {diff_data['to_version']}\n\n"
        
        # Summary
        summary = diff_data['summary']
        md += "## Summary\n\n"
        md += f"- **Breaking Changes**: {summary['breaking_changes']}\n"
        md += f"- **New Features**: {summary['new_features']}\n"
        md += f"- **Total Changes**: {summary['total_changes']}\n\n"
        
        # Breaking changes
        if diff_data['changes']['breaking_changes']:
            md += "## ⚠️ Breaking Changes\n\n"
            for change in diff_data['changes']['breaking_changes']:
                md += f"- **{change['type']}**: {change['description']}\n"
        
        # New features
        if diff_data['changes']['new_features']:
            md += "## ✨ New Features\n\n"
            for change in diff_data['changes']['new_features']:
                md += f"- **{change['type']}**: {change['description']}\n"
        
        # Migration guide
        if diff_data['migration_guide']['required_actions']:
            md += "## 📋 Migration Checklist\n\n"
            for action in diff_data['migration_guide']['required_actions']:
                md += f"- [ ] **{action['action']}**: {action['description']}\n"
        
        return md

def main():
    if len(sys.argv) < 4:
        print("Usage: python generate_api_diff.py <base_url> <from_version> <to_version> [format]")
        sys.exit(1)
    
    base_url = sys.argv[1]
    from_version = sys.argv[2]
    to_version = sys.argv[3]
    format_type = sys.argv[4] if len(sys.argv) > 4 else 'json'
    
    generator = APIDiffGenerator(base_url)
    diff_data = generator.generate_diff(from_version, to_version)
    
    if 'error' in diff_data:
        print(f"Error: {diff_data['error']}")
        sys.exit(1)
    
    output = generator.export_diff(diff_data, format_type)
    print(output)

if __name__ == "__main__":
    main()
```

## Migration Guides

### v1.0 to v1.1 Migration

````markdown
# Migration Guide: v1.0 → v1.1

## Overview
Version 1.1 introduces new fields and enhanced functionality while maintaining full backwards compatibility.

## New Features
- **Pattern Categories**: Patterns now include a `category` field
- **Confidence Scores**: Detection confidence ratings added
- **Enhanced Metadata**: Additional fields for better pattern management

## Code Examples

### Before (v1.0)
```python
import requests

# Get patterns
response = requests.get('http://localhost:8080/api/v1/patterns')
patterns = response.json()

for pattern in patterns:
    print(f"Pattern: {pattern['name']}")
    print(f"Severity: {pattern['severity']}")
````

### After (v1.1) - Enhanced

```python
import requests

# Get patterns with new fields
response = requests.get('http://localhost:8080/api/v1/patterns')
patterns = response.json()

for pattern in patterns:
    print(f"Pattern: {pattern['name']}")
    print(f"Severity: {pattern['severity']}")
    
    # New fields (optional, for enhanced functionality)
    if 'category' in pattern:
        print(f"Category: {pattern['category']}")
    if 'confidence' in pattern:
        print(f"Confidence: {pattern['confidence']}")
```

## Breaking Changes

❌ **None** - This is a backwards-compatible release.

## Action Required

✅ **None** - Existing code will continue to work without modifications.

## Recommended Updates

- Update your models to include new fields
- Consider using confidence scores for filtering
- Use categories for pattern organization

```text
# Pattern migration example here
```

### v1.x to v2.0 Migration (Breaking Changes)

```markdown
# Migration Guide: v1.x → v2.0

## Overview
Version 2.0 introduces significant architectural improvements but includes breaking changes.

## Breaking Changes

### 1. Request/Response Structure Changes

**Old (v1.x):**
```json
{
  "pattern": "(?i)(union.*select)",
  "severity": "high",
  "enabled": true
}
````

**New (v2.0):**

```json
{
  "detection_rule": {
    "regex_pattern": "(?i)(union.*select)",
    "risk_level": "critical",
    "active": true,
    "metadata": {
      "category": "sql_injection",
      "confidence_threshold": 0.8
    }
  }
}
```

### 2. Endpoint Changes

| v1.x Endpoint           | v2.0 Endpoint             | Status  |
| ----------------------- | ------------------------- | ------- |
| `/api/v1/patterns`      | `/api/v2/detection-rules` | Renamed |
| `/api/v1/alerts`        | `/api/v2/notifications`   | Renamed |
| `/api/v1/config/reload` | `/api/v2/system/reload`   | Moved   |

### 3. Field Mapping

| v1.x Field | v2.0 Field                     | Notes            |
| ---------- | ------------------------------ | ---------------- |
| `pattern`  | `detection_rule.regex_pattern` | Nested structure |
| `severity` | `detection_rule.risk_level`    | Values changed   |
| `enabled`  | `detection_rule.active`        | Renamed          |

## Migration Steps

### Step 1: Update Client Code

```python
# Before (v1.x)
class PatternClient:
    def create_pattern(self, pattern_data):
        response = requests.post('/api/v1/patterns', json={
            'pattern': pattern_data['regex'],
            'severity': pattern_data['severity'],
            'enabled': True
        })
        return response.json()

# After (v2.0)
class DetectionRuleClient:
    def create_detection_rule(self, rule_data):
        response = requests.post('/api/v2/detection-rules', json={
            'detection_rule': {
                'regex_pattern': rule_data['regex'],
                'risk_level': self.map_severity(rule_data['severity']),
                'active': True,
                'metadata': {
                    'category': rule_data.get('category', 'other'),
                    'confidence_threshold': rule_data.get('confidence', 0.8)
                }
            }
        })
        return response.json()
    
    def map_severity(self, old_severity):
        mapping = {
            'low': 'info',
            'medium': 'warning', 
            'high': 'critical'
        }
        return mapping.get(old_severity, 'warning')
```

### Step 2: Update Configuration

```yaml
# Before (v1.x config)
patterns:
  sql_injection:
    pattern: "(?i)(union.*select)"
    severity: "high"
    enabled: true

# After (v2.0 config)
detection_rules:
  sql_injection:
    regex_pattern: "(?i)(union.*select)"
    risk_level: "critical"
    active: true
    metadata:
      category: "injection"
      confidence_threshold: 0.9
```

### Step 3: Test Migration

```bash
# Run migration validation
python scripts/validate_migration.py --from v1.2 --to v2.0

# Test with sample data
python scripts/test_api_migration.py --config test-migration.yaml
```

## Timeline

- **v1.x Support**: Continues until 2026-01-15
- **Migration Window**: 6 months overlap (both versions supported)
- **v2.0 Stable**: Available now

## Support

- Migration scripts: `scripts/migrate_v1_to_v2.py`
- Validation tools: `scripts/validate_migration.py`
- Documentation: [v2.0 API Reference](../API_REFERENCE.md)

```text
# Migration support tools example
```

## Version Lifecycle Management

### Deprecation Process

```python
#!/usr/bin/env python3
# scripts/deprecation_manager.py

import json
import datetime
from typing import Dict, List
from pathlib import Path

class DeprecationManager:
    def __init__(self, config_file: str = "deprecation_config.json"):
        self.config_file = Path(config_file)
        self.load_config()
    
    def load_config(self):
        """Load deprecation configuration"""
        if self.config_file.exists():
            with open(self.config_file) as f:
                self.config = json.load(f)
        else:
            self.config = {
                "deprecated_versions": {},
                "deprecation_policy": {
                    "warning_period_months": 6,
                    "support_period_years": 2
                }
            }
    
    def deprecate_version(self, version: str, reason: str, replacement: str = None):
        """Mark a version as deprecated"""
        deprecation_date = datetime.datetime.now().isoformat()
        end_of_life = (datetime.datetime.now() + 
                      datetime.timedelta(days=365 * self.config["deprecation_policy"]["support_period_years"])).isoformat()
        
        self.config["deprecated_versions"][version] = {
            "deprecation_date": deprecation_date,
            "end_of_life": end_of_life,
            "reason": reason,
            "replacement": replacement,
            "status": "deprecated"
        }
        
        self.save_config()
        print(f"Version {version} marked as deprecated")
    
    def check_deprecation_status(self, version: str) -> Dict:
        """Check if a version is deprecated"""
        if version in self.config["deprecated_versions"]:
            dep_info = self.config["deprecated_versions"][version]
            
            # Check if end of life has passed
            eol_date = datetime.datetime.fromisoformat(dep_info["end_of_life"])
            if datetime.datetime.now() > eol_date:
                dep_info["status"] = "unsupported"
            
            return dep_info
        
        return {"status": "supported"}
    
    def generate_deprecation_notice(self) -> str:
        """Generate deprecation notice for documentation"""
        notice = "# API Version Deprecation Notice\n\n"
        
        for version, info in self.config["deprecated_versions"].items():
            if info["status"] == "deprecated":
                notice += f"## Version {version}\n\n"
                notice += f"**Status**: {info['status'].title()}\n"
                notice += f"**Deprecated**: {info['deprecation_date'][:10]}\n"
                notice += f"**End of Life**: {info['end_of_life'][:10]}\n"
                notice += f"**Reason**: {info['reason']}\n"
                
                if info.get('replacement'):
                    notice += f"**Replacement**: {info['replacement']}\n"
                
                notice += "\n"
        
        return notice
    
    def save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)

# Example usage
if __name__ == "__main__":
    manager = DeprecationManager()
    
    # Example: Deprecate v1.0
    manager.deprecate_version(
        version="v1.0",
        reason="Security vulnerabilities in authentication mechanism",
        replacement="v1.2"
    )
    
    print(manager.generate_deprecation_notice())
````

## Automated Testing for API Versions

```python
#!/usr/bin/env python3
# tests/test_api_versions.py

import pytest
import requests
from typing import List, Dict
import json

class TestAPIVersions:
    """Test suite for API version compatibility"""
    
    base_url = "http://localhost:8080"
    supported_versions = ["v1.0", "v1.1", "v1.2", "v2.0"]
    
    @pytest.mark.parametrize("version", supported_versions)
    def test_version_health_endpoint(self, version):
        """Test health endpoint for all supported versions"""
        response = requests.get(f"{self.base_url}/api/{version}/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
    
    @pytest.mark.parametrize("version", ["v1.0", "v1.1", "v1.2"])
    def test_v1_x_compatibility(self, version):
        """Test backwards compatibility within v1.x"""
        # Test pattern endpoint structure
        response = requests.get(f"{self.base_url}/api/{version}/patterns")
        assert response.status_code == 200
        
        patterns = response.json()
        for pattern in patterns:
            # Required fields in all v1.x versions
            assert "id" in pattern
            assert "name" in pattern
            assert "pattern" in pattern
            assert "severity" in pattern
    
    def test_v2_breaking_changes(self):
        """Test that v2.0 has expected breaking changes"""
        # v2.0 should use different endpoint names
        v1_response = requests.get(f"{self.base_url}/api/v1/patterns")
        v2_response = requests.get(f"{self.base_url}/api/v2/patterns")
        
        # v1 should work, v2 should not (endpoint renamed)
        assert v1_response.status_code == 200
        assert v2_response.status_code == 404
        
        # v2 should work with new endpoint name
        v2_new_response = requests.get(f"{self.base_url}/api/v2/detection-rules")
        assert v2_new_response.status_code == 200
    
    def test_version_negotiation(self):
        """Test content negotiation for API versions"""
        headers = {
            "Accept": "application/vnd.nsm.v1+json"
        }
        response = requests.get(f"{self.base_url}/api/patterns", headers=headers)
        assert response.status_code == 200
        assert response.headers.get("API-Version") == "1.2"  # Latest v1.x
    
    @pytest.mark.parametrize("from_version,to_version", [
        ("v1.0", "v1.1"),
        ("v1.1", "v1.2"),
    ])
    def test_migration_compatibility(self, from_version, to_version):
        """Test that migrations don't break existing functionality"""
        # Get data from older version
        old_response = requests.get(f"{self.base_url}/api/{from_version}/patterns")
        old_data = old_response.json()
        
        # Get data from newer version
        new_response = requests.get(f"{self.base_url}/api/{to_version}/patterns")
        new_data = new_response.json()
        
        # Check that all old fields are still present
        for old_pattern in old_data:
            matching_new = next(
                (p for p in new_data if p["id"] == old_pattern["id"]), 
                None
            )
            assert matching_new is not None
            
            # All old fields should be present
            for field in old_pattern:
                assert field in matching_new
                # Values should be compatible (allowing for type coercion)
                assert str(old_pattern[field]) == str(matching_new[field])
```

______________________________________________________________________

**Related Documentation:**

- [API Reference](../API_REFERENCE.md)
- [Getting Started Guide](../getting-started.md)
- [Release Process](../process/releases.md)
- [Configuration Guide](../CONFIGURATION.md)
