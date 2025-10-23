# Contributing to NMAP Automator

Thank you for your interest in contributing to NMAP Automator! We welcome contributions from the community and are pleased to have you join us.

## 🤝 How to Contribute

### 🐛 Reporting Issues
- Use the [GitHub Issues](https://github.com/Mosesjuju/nmap-automator/issues) page
- Search existing issues before creating a new one
- Include detailed information about the bug, your environment, and steps to reproduce
- Attach relevant log files and scan outputs (sanitize sensitive information)

### 💡 Suggesting Features
- Open a [GitHub Discussion](https://github.com/Mosesjuju/nmap-automator/discussions) for feature ideas
- Describe the problem you're trying to solve
- Provide examples of how the feature would be used
- Consider if it fits the project's scope and philosophy

### 🔧 Code Contributions

#### Development Setup
```bash
# Fork and clone the repository
git clone https://github.com/yourusername/nmap-automator.git
cd nmap-automator

# Create a development branch
git checkout -b feature/your-feature-name

# Set up virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest black flake8 mypy
```

#### Development Guidelines

**Code Style:**
- Follow PEP 8 Python style guide
- Use `black` for code formatting: `black .`
- Run `flake8` for linting: `flake8 .`
- Use type hints where appropriate

**Testing:**
- Write tests for new features
- Ensure all tests pass: `python -m pytest`
- Test with multiple target types (IP, domain, network ranges)
- Verify speed presets work correctly

**Documentation:**
- Update docstrings for new functions
- Add usage examples for new features
- Update README.md if adding user-facing features
- Include performance benchmarks for new speed optimizations

#### Commit Message Format
```
type(scope): brief description

Detailed explanation of what changed and why.
Include any breaking changes or migration notes.

Closes #issue-number
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code formatting changes
- `refactor`: Code restructuring
- `test`: Adding/updating tests
- `perf`: Performance improvements

#### Pull Request Process

1. **Create a Feature Branch**
   ```bash
   git checkout -b feature/amazing-new-feature
   ```

2. **Make Your Changes**
   - Follow the development guidelines above
   - Test thoroughly
   - Update documentation

3. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "feat(scanner): add GPU-accelerated scanning mode"
   ```

4. **Push and Create PR**
   ```bash
   git push origin feature/amazing-new-feature
   ```
   - Open a Pull Request on GitHub
   - Fill out the PR template completely
   - Link relevant issues

5. **Code Review Process**
   - Maintainers will review your code
   - Address any feedback or requests for changes
   - Once approved, your PR will be merged

## 🎯 Areas for Contribution

### High Priority
- 🚀 **Performance Optimizations** - New speed presets and scanning techniques
- 🤖 **AI Integrations** - Support for new AI providers and analysis methods
- 🔗 **Tool Chaining** - Integration with additional security tools
- 🛡️ **Evasion Techniques** - Advanced IDS/firewall bypass methods

### Medium Priority
- 📊 **Reporting Enhancements** - Better output formats and visualizations
- 🌐 **Protocol Support** - IPv6, HTTP/3, new service detection
- 📱 **Platform Support** - Windows, macOS compatibility improvements
- 🔧 **Configuration** - Enhanced configuration management

### Community Contributions
- 📚 **Documentation** - Tutorials, examples, use cases
- 🧪 **Testing** - Test cases, CI/CD improvements
- 🌍 **Localization** - Multi-language support
- 🎨 **UI/UX** - CLI improvements, progress indicators

## 📋 Pull Request Template

When creating a PR, please include:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update
- [ ] Performance improvement

## Testing
- [ ] Tests added/updated
- [ ] All tests pass
- [ ] Manual testing completed

## Screenshots/Examples
(If applicable)

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review of code completed
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] No sensitive information included
```

## 🛡️ Security Considerations

**Important:** This tool is for authorized security testing only.

- Only test systems you own or have explicit permission to test
- Do not include real target information in PRs
- Sanitize all log files and examples
- Use test targets like `scanme.nmap.org` for examples
- Follow responsible disclosure for any vulnerabilities found

## 🏆 Recognition

Contributors will be recognized in:
- README.md acknowledgments
- Release notes for significant contributions
- GitHub contributor graphs
- Special mentions for innovative features

## 📞 Questions?

- 💬 **Discussions**: Use GitHub Discussions for questions
- 🐛 **Issues**: Use GitHub Issues for bugs
- 📧 **Direct Contact**: For sensitive security matters

## 📄 Code of Conduct

By participating in this project, you agree to:
- Be respectful and inclusive
- Focus on constructive feedback
- Help maintain a welcoming environment
- Follow responsible disclosure practices

---

**"The quieter you become, the more you can hear"** 🥷

Thank you for helping make NMAP Automator better for everyone!