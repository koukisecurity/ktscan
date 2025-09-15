# Contributing to KTScan

Thank you for your interest in contributing to KTScan! We welcome contributions from the community.

## Contributor License Agreement

Before we can accept your contributions, we need you to sign our Contributor License Agreement (CLA). This is a standard process that ensures we can legally accept and distribute your contributions.

**The process is automated!** When you submit your first pull request, our CLA Assistant bot will automatically:
1. Check if you've already signed our CLA
2. If not, provide you with a link to sign it online
3. Once signed, automatically update your PR status

You can review our CLA document here: [Individual CLA](https://gist.github.com/SOcr4t3s/dc91a5772f07885686ee156f45972f2a)

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/[YOUR_USERNAME]/ktscan.git
   cd ktscan
   ```
3. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

1. **Install dependencies**:
   ```bash
   pip install -e .
   pip install -r requirements-dev.txt  # if you have dev requirements
   ```

2. **Run tests**:
   ```bash
   pytest
   ```

3. **Run linting**:
   ```bash
   # Add your linting commands here
   ```

## Making Changes

1. **Make your changes** in your feature branch
2. **Add tests** for any new functionality
3. **Update documentation** if needed
4. **Ensure all tests pass**
5. **Commit your changes**:
   ```bash
   git commit -m "Brief description of your changes"
   ```
6. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

## Submitting Changes

1. **Open a Pull Request** from your feature branch to our main branch
2. **Fill out the PR template** (if we have one)
3. **Wait for review** - we'll review your changes and may request modifications
4. **Address feedback** if any
5. **CLA Check** - ensure your CLA is on file (we'll check this automatically)

## Code Style

- Follow PEP 8 for Python code
- Use meaningful variable and function names
- Add docstrings to functions and classes
- Keep lines under 100 characters when possible

## Reporting Issues

If you find a bug or have a feature request:
1. **Search existing issues** first
2. **Create a new issue** with:
   - Clear description
   - Steps to reproduce (for bugs)
   - Expected vs actual behavior
   - Environment details (OS, Python version, etc.)

## Questions?

If you have questions about contributing, please:
- Open an issue with the "question" label
- Email us at [YOUR_CONTACT_EMAIL]

## License

By contributing to KTScan, you agree that your contributions will be licensed under the Apache 2.0 License.

## Code of Conduct

Please be respectful and professional in all interactions. We want to maintain a welcoming environment for all contributors.