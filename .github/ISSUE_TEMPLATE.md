---
title: "{{ env.VULN_ID }} ({{ env.VULN_DEP_NAME }}) found on {{ env.NODEJS_STREAM }}"
labels: {{ env.ISSUE_LABELS }}
assignees:
---

A new vulnerability for {{ env.VULN_DEP_NAME }} {{ env.VULN_DEP_VERSION }} was found:
Vulnerability ID: {{ env.VULN_ID }}
Vulnerability URL: {{ env.VULN_URL }}
{% if env.VULN_SOURCE == 'npm' and env.VULN_MAIN_DEP_NAME %}
Main Dependency: {{ env.VULN_MAIN_DEP_NAME }}
Main Dependency Path: {{ env.VULN_MAIN_DEP_PATH }}
{% endif %}
Failed run: {{ env.ACTION_URL }}
