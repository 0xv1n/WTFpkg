---
name: "{{ replace .File.ContentBaseName "-" " " | title }}"
packageManager: "npm"
slug: "{{ .File.ContentBaseName }}"
category: "Code Execution"
severity: "medium"
platform:
  - "Linux"
description: "Describe the technique, its conditions, and its impact."
descriptionCitations: []
prerequisites: []
prerequisitesCitations: []
attackScenarios:
  - title: "Scenario name"
    description: "Describe the attack and its conditions."
    citations: []
    commands:
      - code: |
          # Example command
        language: "bash"
detection:
  - title: "Detection method"
    description: "Describe observable evidence."
    citations: []
    commands:
      - code: |
          # Example detection command
        language: "bash"
mitigation:
  - "Describe an actionable mitigation."
mitigationCitations: []
references:
  - title: "Primary source title"
    url: "https://example.com/primary-source"
created: "{{ .Date }}"
updated: "{{ .Date }}"
---
