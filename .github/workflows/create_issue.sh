#!/bin/bash

# GitHub Issue Creation Script
# Creates or updates GitHub issues for vulnerabilities with automatic label management

set -e

# Validate required environment variables
required_vars=("VULN_ID" "VULN_URL" "VULN_DEP_NAME" "VULN_DEP_VERSION" "VULN_SOURCE" "NODEJS_STREAM" "ACTION_URL" "LABELS" "GITHUB_TOKEN")

for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
        echo "Error: Required environment variable $var is not set"
        exit 1
    fi
done

# Set variables from environment
VULN_ID="${VULN_ID}"
VULN_URL="${VULN_URL}"
VULN_DEP_NAME="${VULN_DEP_NAME}"
VULN_DEP_VERSION="${VULN_DEP_VERSION}"
VULN_SOURCE="${VULN_SOURCE}"
VULN_MAIN_DEP_NAME="${VULN_MAIN_DEP_NAME:-}"
VULN_MAIN_DEP_PATH="${VULN_MAIN_DEP_PATH:-}"
NODEJS_STREAM="${NODEJS_STREAM}"
ACTION_URL="${ACTION_URL}"
LABELS="${LABELS}"

# Create issue title
ISSUE_TITLE="${VULN_ID} (${VULN_DEP_NAME}) found on ${NODEJS_STREAM}"

# Create issue body
ISSUE_BODY="A new vulnerability for ${VULN_DEP_NAME} ${VULN_DEP_VERSION} was found:
Vulnerability ID: ${VULN_ID}
Vulnerability URL: ${VULN_URL}"

# Add npm-specific info if applicable
if [ "${VULN_SOURCE}" = "npm" ] && [ -n "${VULN_MAIN_DEP_NAME}" ]; then
    ISSUE_BODY="${ISSUE_BODY}
Main Dependency: ${VULN_MAIN_DEP_NAME}
Main Dependency Path: ${VULN_MAIN_DEP_PATH}"
fi

ISSUE_BODY="${ISSUE_BODY}
Failed run: ${ACTION_URL}"

echo "Processing vulnerability: ${VULN_ID}"
echo "Issue title: ${ISSUE_TITLE}"
echo "Labels: ${LABELS}"

# Check if issue already exists
EXISTING_ISSUE=$(gh issue list --search "in:title ${ISSUE_TITLE}" --state open --json number,title --jq '.[] | select(.title == "'"${ISSUE_TITLE}"'") | .number')

if [ -n "${EXISTING_ISSUE}" ]; then
    echo "Updating existing issue #${EXISTING_ISSUE}: ${ISSUE_TITLE}"
    gh issue edit "${EXISTING_ISSUE}" --body "${ISSUE_BODY}"
    echo "Updated issue: https://github.com/${GITHUB_REPOSITORY}/issues/${EXISTING_ISSUE}"
else
    echo "Creating new issue: ${ISSUE_TITLE}"
    # Create issue first without labels to avoid label not found errors
    ISSUE_URL=$(gh issue create --title "${ISSUE_TITLE}" --body "${ISSUE_BODY}")
    ISSUE_NUMBER=$(echo "${ISSUE_URL}" | sed 's/.*\/issues\///')
    echo "Created issue: ${ISSUE_URL}"
    
    # Add labels one by one, creating them if they don't exist
    IFS=',' read -ra LABEL_ARRAY <<< "${LABELS}"
    for label in "${LABEL_ARRAY[@]}"; do
        # Trim whitespace
        label=$(echo "${label}" | xargs)
        echo "Adding label: ${label}"
        
        # Try to add the label, if it fails, create it first then add it
        if ! gh issue edit "${ISSUE_NUMBER}" --add-label "${label}" 2>/dev/null; then
            echo "Label '${label}' doesn't exist, creating it..."
            
            # Set label color based on label type
            case "${label}" in
                *CRITICAL*)
                    LABEL_COLOR="d73a49"  # Red
                    LABEL_DESC="Critical severity vulnerability"
                    ;;
                *HIGH*)
                    LABEL_COLOR="fd7e14"  # Orange
                    LABEL_DESC="High severity vulnerability"
                    ;;
                *MODERATE*|*MEDIUM*)
                    LABEL_COLOR="ffc107"  # Yellow
                    LABEL_DESC="Moderate severity vulnerability"
                    ;;
                *LOW*)
                    LABEL_COLOR="28a745"  # Green
                    LABEL_DESC="Low severity vulnerability"
                    ;;
                *NPM*)
                    LABEL_COLOR="cb3837"  # NPM red
                    LABEL_DESC="NPM package vulnerability"
                    ;;
                *v[0-9]*\.x*)
                    LABEL_COLOR="0366d6"  # Blue
                    LABEL_DESC="Version-specific label"
                    ;;
                *nsolid*)
                    LABEL_COLOR="6f42c1"  # Purple
                    LABEL_DESC="N|Solid related"
                    ;;
                *)
                    LABEL_COLOR="0366d6"  # Default blue
                    LABEL_DESC="Auto-created vulnerability label"
                    ;;
            esac
            
            # Create the label with appropriate color and description
            if gh label create "${label}" --color "${LABEL_COLOR}" --description "${LABEL_DESC}" 2>/dev/null; then
                echo "Created label '${label}' with color #${LABEL_COLOR}"
            else
                echo "Warning: Failed to create label '${label}' (may already exist)"
            fi
            
            # Try to add the label again
            if gh issue edit "${ISSUE_NUMBER}" --add-label "${label}" 2>/dev/null; then
                echo "Successfully added label: ${label}"
            else
                echo "Warning: Failed to add label: ${label}"
            fi
        else
            echo "Successfully added existing label: ${label}"
        fi
    done
    
    echo "Issue creation completed with all labels applied"
fi

echo "Issue processing completed successfully"
