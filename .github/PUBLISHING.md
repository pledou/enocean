# Publishing enocean-extended to PyPI

This package uses GitHub Actions for automated publishing to PyPI.

## Setup (One-time configuration)

### Option 1: Trusted Publishing (Recommended - No tokens needed!)

1. **On PyPI**:
   - Go to https://pypi.org/manage/account/publishing/
   - Click "Add a new pending publisher"
   - Fill in:
     - PyPI Project Name: `enocean-extended`
     - Owner: `pledou`
     - Repository name: `enocean`
     - Workflow name: `publish-to-pypi.yml`
     - Environment name: `pypi`

2. **That's it!** No tokens needed. GitHub will authenticate automatically.

### Option 2: API Token (Alternative)

If you prefer using an API token:

1. Create a token at https://pypi.org/manage/account/token/
2. In your GitHub repository, go to Settings → Secrets and variables → Actions
3. Create a new repository secret named `PYPI_API_TOKEN`
4. Update the workflow to use the token instead of trusted publishing

## How to Publish

### Automatic Publishing (on Release)

1. **Update version** in `pyproject.toml` and `setup.py`
2. **Commit and push** changes
3. **Create a GitHub release**:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
   Or use GitHub UI: Releases → Draft a new release

4. GitHub Actions will automatically:
   - Build the package
   - Run tests
   - Publish to PyPI

### Manual Publishing (for testing)

1. Go to Actions tab in GitHub
2. Select "Publish to PyPI" workflow
3. Click "Run workflow"
4. This will publish to TestPyPI for testing

## Version Numbering

Follow [Semantic Versioning](https://semver.org/):
- `1.0.0` - Major release
- `1.0.1` - Patch/bugfix
- `1.1.0` - Minor feature addition
- `2.0.0` - Breaking changes

## Pre-release Checklist

- [ ] Update version in `pyproject.toml`
- [ ] Update version in `setup.py`
- [ ] Update `CHANGELOG.md`
- [ ] Update `README.md` if needed
- [ ] Run tests locally: `pytest`
- [ ] Build locally: `python -m build`
- [ ] Check package: `twine check dist/*`
- [ ] Commit all changes
- [ ] Create and push tag
- [ ] Create GitHub release
- [ ] Verify workflow completes successfully
- [ ] Check package on PyPI
