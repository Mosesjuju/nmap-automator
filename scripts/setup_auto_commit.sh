#!/bin/bash
# SecureScout Auto-Commit Setup
# Sets up automatic version control for SecureScout development

SECURESCOUT_DIR="/home/kali/NMAP"
SCRIPT_DIR="$SECURESCOUT_DIR/scripts"

echo "🔧 Setting up SecureScout Auto-Commit System..."

# Create bash alias for quick commits
echo "📝 Adding bash aliases..."
{
    echo ""
    echo "# SecureScout Auto-Commit Aliases"
    echo "alias scommit='$SCRIPT_DIR/auto_commit.sh'"
    echo "alias sstatus='cd $SECURESCOUT_DIR && git status'"
    echo "alias slog='cd $SECURESCOUT_DIR && git log --oneline -10'"
    echo "alias spush='cd $SECURESCOUT_DIR && git push'"
} >> ~/.bashrc

# Create zsh aliases if zsh is being used
if [ "$SHELL" = "/usr/bin/zsh" ] || [ "$SHELL" = "/bin/zsh" ]; then
    {
        echo ""
        echo "# SecureScout Auto-Commit Aliases"
        echo "alias scommit='$SCRIPT_DIR/auto_commit.sh'"
        echo "alias sstatus='cd $SECURESCOUT_DIR && git status'"
        echo "alias slog='cd $SECURESCOUT_DIR && git log --oneline -10'"
        echo "alias spush='cd $SECURESCOUT_DIR && git push'"
    } >> ~/.zshrc
fi

# Setup cron job for automatic commits (every 30 minutes during work hours)
echo "⏰ Setting up cron job for auto-commits..."
(crontab -l 2>/dev/null; echo "*/30 8-18 * * 1-5 cd $SECURESCOUT_DIR && $SCRIPT_DIR/auto_commit.sh >/dev/null 2>&1") | crontab -

echo "✅ Auto-commit system setup complete!"
echo ""
echo "🎯 Available commands:"
echo "  scommit  - Manual auto-commit"
echo "  sstatus  - Check git status"
echo "  slog     - View recent commits"
echo "  spush    - Push to remote repository"
echo ""
echo "⏰ Automatic commits scheduled every 30 minutes (8AM-6PM, Mon-Fri)"
echo "🔄 Restart your terminal or run 'source ~/.bashrc' to use aliases"