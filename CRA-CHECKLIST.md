# CRA-Friendly Checklist

This project voluntarily documents its security practices.
This information is provided "as is", without warranties or guarantees. See the project's license for more details.

The maintainers and contributors:

* have no obligations under the EU CRA,
* are not Manufacturers, Importers, or Economic Operators,
* assume no financial, contractual, or legal liability,
* and do not provide CRA compliance assurances.

Anyone incorporating this software into commercial products remains solely responsible for such products, including regulatory compliance, risk assessment, and vulnerability management.

Structure follows the voluntary [CRA Readiness Guide for maintainers and developers](https://best.openssf.org/CRA-Brief-Guide-for-OSS-Developers). Status was last verified on 2026-09-24; settings-based rows were read from the GitHub API on that date.

| Item | Status | Evidence | Known gaps |
| :-- | :-- | :-- | :-- |
| Cybersecurity and vulnerability management policy | In place | [SECURITY.md](https://github.com/GeeksikhSecurity/mcp-sentinel-scanner/blob/main/SECURITY.md): reporting channels, response timeline, update process, disclosure policy, supported-versions table | The supported-versions table lists 2.1.x and 2.0.x, but `pyproject.toml` is at 1.5.0 and no release is tagged; the end-of-life plan needs reconciling with real versions |
| Contributing guidance | In place | [CONTRIBUTING.md](https://github.com/GeeksikhSecurity/mcp-sentinel-scanner/blob/main/CONTRIBUTING.md) | Clone URL names the `mcp-security` org, not this repository; secure-development practices are not linked explicitly |
| Release documentation | Partial | [CHANGELOG.md](https://github.com/GeeksikhSecurity/mcp-sentinel-scanner/blob/main/CHANGELOG.md) (Keep a Changelog format, has an Unreleased section) | No tagged releases or GitHub Releases yet, so there are no per-release security-fix notes |
| Bug reporting guide | In place | "Bug Reports" section of [CONTRIBUTING.md](https://github.com/GeeksikhSecurity/mcp-sentinel-scanner/blob/main/CONTRIBUTING.md); [issue templates](https://github.com/GeeksikhSecurity/mcp-sentinel-scanner/blob/main/.github/ISSUE_TEMPLATE); SECURITY.md says not to use public issues for vulnerabilities | None known |
| MFA enforcement | In place | Two-factor authentication is enabled on the owning GitHub account (API check, 2026-09-24) | Single-maintainer project |
| Branch protection | Partial | `main` is protected: rules apply to administrators and force-push is disabled (API check, 2026-09-24) | Zero required approving reviews and no required status checks |
| Licence file | In place | [LICENSE](https://github.com/GeeksikhSecurity/mcp-sentinel-scanner/blob/main/LICENSE) (MIT) | None known |
| OSPS Baseline Level 1 | Not assessed | Target: [baseline.openssf.org](https://baseline.openssf.org) | No checklist completed yet |
| Machine-readable posture | In place | [security-insights.yml](https://github.com/GeeksikhSecurity/mcp-sentinel-scanner/blob/main/security-insights.yml) (Security Insights v2.2.0, validated with `cue vet`); [Scorecard workflow](https://github.com/GeeksikhSecurity/mcp-sentinel-scanner/blob/main/.github/workflows/scorecard.yml) | The Scorecard score is not published in this file |
| Pinned CI dependencies | In place | Every GitHub Action in `.github/workflows/` is pinned to a commit SHA; enforced by `scripts/check-cra-checklist.py` in CI | Release publishing still uses a static `PYPI_API_TOKEN` rather than PyPI trusted publishing |

## Verifying this page

```bash
python3 scripts/check-cra-checklist.py
cue vet -c schema.cue security-insights.yml -d '#SecurityInsights'   # schema.cue from ossf/security-insights-spec at v2.2.0
```
