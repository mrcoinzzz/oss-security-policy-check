# OSS Security Policy Check

A small command line tool that checks whether an open-source repository has clear security reporting and disclosure guidance.

It helps maintainers spot missing security policy basics before users or researchers need them.

## Checks

- `SECURITY.md` or `.github/SECURITY.md`
- Contact or reporting instructions
- Supported versions guidance
- Responsible disclosure wording
- Vulnerability impact language
- Dependency or supply-chain mention
- GitHub Actions workflow presence
- Dependabot configuration, when present
- License and README basics

## Install

```bash
python3 -m pip install -e .
```

## Usage

```bash
oss-security-policy-check
```

Check another repository:

```bash
oss-security-policy-check /path/to/project
```

JSON output:

```bash
oss-security-policy-check /path/to/project --format json
```

Markdown report:

```bash
oss-security-policy-check /path/to/project --format markdown
```

Write a report to a file:

```bash
oss-security-policy-check /path/to/project --format markdown --output security-report.md
```

Print a starter `SECURITY.md` template:

```bash
oss-security-policy-check --print-template
```

Write a starter template to a file:

```bash
oss-security-policy-check --write-template SECURITY.md
```

Use `--force` to overwrite an existing target file.

## Why this exists

Security reporting is often treated as optional until the moment it matters. This tool gives maintainers a small, local checklist for making vulnerability handling easier to find and easier to follow.

## Roadmap

- GitHub security advisory readiness checks
- Dependency workflow detection across ecosystems
- Optional OpenAI-assisted policy review

## License

MIT
