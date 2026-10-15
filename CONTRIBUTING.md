# Contributing to WTFpkg

Thanks for helping document package manager abuse techniques. This guide covers adding new techniques and new package managers.

## Adding a New Technique

### 1. Create the file

Create a new Markdown file in `content/techniques/` named `<pm>-<short-name>.md`:

```
content/techniques/npm-my-new-technique.md
```

### 2. Fill in the frontmatter

Every technique file is **pure YAML frontmatter** (no Markdown body). Here's the full template:

```yaml
---
name: "Technique Display Name"
packageManager: "npm"
slug: "npm-my-new-technique"
category: "Code Execution"
severity: "high"
platform:
  - "Linux"
  - "macOS"
  - "Windows"
description: "A clear explanation of what this technique does, how it works, and why it matters. 2-4 sentences."
descriptionCitations: [1]
prerequisites:
  - "What the attacker needs before exploiting this"
  - "e.g. ability to publish a package, network position, etc."
prerequisitesCitations: [1]
attackScenarios:
  - title: "Scenario Name"
    description: "What this specific attack does and how."
    citations: [1]
    commands:
      - label: "Optional label describing this code block"
        code: |
          # The actual command or code
          echo "example"
        language: "bash"
detection:
  - title: "Detection Method Name"
    description: "How to detect this technique."
    citations: [1]
    commands:
      - code: |
          # Detection command
          grep -r "suspicious-pattern" /etc/
        language: "bash"
mitigation:
  - "Short actionable mitigation step"
  - "Another mitigation step"
mitigationCitations: [1]
references:
  - title: "Primary upstream source title"
    url: "https://upstream.example.org/documentation"
created: "YYYY-MM-DD"
updated: "YYYY-MM-DD"
---
```

Every factual claim must have a claim-level numeric citation. Citation fields contain one-based numbers that point to entries in `references`; markers render as accessible links such as `[1]` and reference entries receive stable page anchors `ref-1`, `ref-2`, and so on. Add the marker to the field containing the claim: `descriptionCitations`, `prerequisitesCitations`, each `attackScenarios[].citations`, each `detection[].citations`, or `mitigationCitations`. Use primary sources whenever available, such as official package-manager documentation, upstream advisories, vulnerability records, standards, or original research. Cite secondary sources only when a primary source cannot support the claim. The Hugo build reports missing or out-of-range citation numbers.

### 3. Valid field values

| Field | Valid Values |
|-------|-------------|
| `packageManager` | `apt`, `pip`, `npm`, `gem`, `cargo`, `brew` |
| `severity` | `critical`, `high`, `medium`, `low` |
| `category` | `Code Execution`, `Supply Chain`, `Source Manipulation`, `Signature Bypass`, or a new one if justified |
| `platform` | `Linux`, `macOS`, `Windows` (list all that apply) |
| `language` (in commands) | `bash`, `python`, `ruby`, `javascript`, `json`, `yaml`, `toml`, `rust`, `ini` |

### 4. Test locally

```bash
hugo server --buildDrafts
```

Visit the package manager's page and verify your technique card appears and the detail page renders correctly.

## Adding a New Package Manager

This requires a few more steps:

1. **Create the PM page** at `content/pm/<name>.md`:
   ```yaml
   ---
   title: "PM Display Name"
   layout: "pm-detail"
   pmKey: "<name>"
   description: "Short ecosystem description"
   ---
   ```

2. **Update `layouts/_default/list.html`** to add the new PM to:
   - `$pmOrder` slice
   - `$pmLabels` dict
   - `$pmDescs` dict
   - `$pmLongDescs` dict

3. **Add CSS** in `assets/css/main.css`:
   - A `--pm-<name>` color variable
   - Card accent, hover, and name color rules

4. **Add at least one technique** in `content/techniques/`.

## Pull Request Process

1. Fork the repo and create a feature branch
2. Add your technique or package manager
3. Test locally with `hugo server --buildDrafts`
4. Submit a PR using the provided template and attach screenshots of technique functioning.
5. Ensure the Hugo build passes in CI

## Severity Guidelines

- **Critical**: Arbitrary code execution with no user interaction beyond a standard install command
- **High**: Code execution requiring specific configuration, or attacks enabling full supply chain compromise
- **Medium**: Attacks requiring privileged access, specific network conditions, or outdated software
- **Low**: Information disclosure or attacks with significant prerequisites
