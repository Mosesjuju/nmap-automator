#!/bin/bash
# SecureScout Auto-Commit Script
# Automatically commits changes with intelligent commit messages

cd "$(dirname "$0")"

# Check if there are any changes
if git diff --quiet && git diff --staged --quiet; then
    echo "📋 No changes to commit"
    exit 0
fi

# Get current timestamp
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Check what types of files changed
CHANGED_FILES=$(git diff --name-only --staged)
MODIFIED_FILES=$(git diff --name-only)

# Combine both lists
ALL_CHANGED_FILES="$CHANGED_FILES $MODIFIED_FILES"

# Determine commit type based on changed files
COMMIT_TYPE="🔧 Update"
COMMIT_MESSAGE="Automated commit - $TIMESTAMP"

if echo "$ALL_CHANGED_FILES" | grep -q "README.md\|\.md$"; then
    COMMIT_TYPE="📚 Documentation"
    COMMIT_MESSAGE="Update documentation - $TIMESTAMP"
elif echo "$ALL_CHANGED_FILES" | grep -q "\.py$"; then
    COMMIT_TYPE="💻 Code"
    COMMIT_MESSAGE="Update code - $TIMESTAMP"
elif echo "$ALL_CHANGED_FILES" | grep -q "config/\|requirements"; then
    COMMIT_TYPE="⚙️ Configuration"
    COMMIT_MESSAGE="Update configuration - $TIMESTAMP"
elif echo "$ALL_CHANGED_FILES" | grep -q "cache/\|logs/"; then
    COMMIT_TYPE="📊 Data"
    COMMIT_MESSAGE="Update cache/logs - $TIMESTAMP"
elif echo "$ALL_CHANGED_FILES" | grep -q "results/"; then
    COMMIT_TYPE="🎯 Results"
    COMMIT_MESSAGE="Update scan results - $TIMESTAMP"
elif echo "$ALL_CHANGED_FILES" | grep -q "tests/"; then
    COMMIT_TYPE="🧪 Tests"
    COMMIT_MESSAGE="Update tests - $TIMESTAMP"
fi

# Add all changes (respecting .gitignore)
git add .

# Create detailed commit message
DETAILED_MESSAGE="$COMMIT_TYPE: $COMMIT_MESSAGE

📁 Changed files:
$(echo "$ALL_CHANGED_FILES" | head -10)

🕒 Auto-committed: $TIMESTAMP
🤖 SecureScout Auto-Commit System"

# Commit with detailed message
git commit -m "$DETAILED_MESSAGE"

if [ $? -eq 0 ]; then
    echo "✅ Auto-commit successful: $COMMIT_TYPE"
    echo "📝 Message: $COMMIT_MESSAGE"
    
    # Show latest commit info
    echo ""
    echo "📊 Latest commit:"
    git log --oneline -1
    
    # Show repository status
    echo ""
    echo "📋 Repository status:"
    git status --short
else
    echo "❌ Auto-commit failed"
    exit 1
fi