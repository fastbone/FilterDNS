# GPL License Options for FilterDNS

This document explains the GNU General Public License (GPL) options available and why GPL-3.0 was chosen for FilterDNS.

## Current License: GPL-3.0

FilterDNS is currently licensed under **GNU General Public License v3.0 (GPL-3.0)**.

## GPL License Versions Comparison

### GPL-2.0 (GNU General Public License v2.0)

**Pros:**
- ✅ Widely used and well-understood
- ✅ Compatible with Linux kernel (Linux uses GPL-2.0)
- ✅ Simpler and shorter than GPL-3.0
- ✅ More permissive regarding patent issues

**Cons:**
- ❌ Older version (1991)
- ❌ Doesn't address modern issues like:
  - Software patents
  - Tivoization (hardware restrictions)
  - DRM (Digital Rights Management) restrictions
- ❌ Less compatible with some other licenses

**Best for:** Projects that need compatibility with Linux kernel or other GPL-2.0 projects.

### GPL-3.0 (GNU General Public License v3.0) ⭐ **CURRENT CHOICE**

**Pros:**
- ✅ Most modern and comprehensive version (2007)
- ✅ Addresses software patents explicitly
- ✅ Prevents "tivoization" (devices that run GPL code but prevent users from modifying it)
- ✅ Better compatibility with Apache 2.0 and other modern licenses
- ✅ Stronger protection against DRM restrictions
- ✅ Recommended by Free Software Foundation for new projects
- ✅ Better internationalization (works better across different legal systems)

**Cons:**
- ❌ Not compatible with GPL-2.0-only projects
- ❌ Longer and more complex than GPL-2.0
- ❌ Some consider it "too restrictive"

**Best for:** New projects, projects that want strongest copyleft protection, projects dealing with modern software distribution.

### LGPL-2.1 / LGPL-3.0 (Lesser General Public License)

**Pros:**
- ✅ Allows linking with proprietary code
- ✅ Good for libraries that need to be used in proprietary applications
- ✅ Less restrictive than GPL

**Cons:**
- ❌ Weaker copyleft protection
- ❌ Allows proprietary applications to use your code without contributing back

**Best for:** Libraries, shared components that need to be used in both free and proprietary software.

### AGPL-3.0 (Affero General Public License v3.0)

**Pros:**
- ✅ Extends GPL-3.0 to cover network/cloud services
- ✅ Requires source code release even for SaaS/web applications
- ✅ Prevents "GPL loophole" where companies run GPL software as a service without sharing code

**Cons:**
- ❌ Most restrictive GPL variant
- ❌ May limit commercial adoption
- ❌ Requires source code release for web services

**Best for:** Web applications, SaaS services, cloud software where you want to ensure source code availability.

## Why GPL-3.0 for FilterDNS?

1. **Modern Protection**: GPL-3.0 provides the best protection against modern threats like software patents and hardware restrictions.

2. **Strong Copyleft**: Ensures that improvements and modifications to FilterDNS remain open source, benefiting the entire community.

3. **FSF Recommendation**: The Free Software Foundation recommends GPL-3.0 for new projects as it's the most current and comprehensive version.

4. **DNS Infrastructure**: DNS proxy software is critical infrastructure. GPL-3.0 ensures transparency and community benefit.

5. **Future-Proof**: GPL-3.0 is designed to work well with modern software distribution methods and legal frameworks.

## License Compatibility

### Can GPL-3.0 code be used with:
- **GPL-2.0-only code**: ❌ No (incompatible)
- **GPL-3.0 code**: ✅ Yes
- **LGPL code**: ✅ Yes (LGPL allows linking with GPL)
- **MIT/Apache 2.0 code**: ✅ Yes (can be included, but result must be GPL-3.0)
- **Proprietary code**: ❌ No (not allowed)

## Changing the License

If you want to change the license:

1. **To GPL-2.0**: You can relicense GPL-3.0 code to GPL-2.0 (downgrade), but you'd lose GPL-3.0 protections.

2. **To LGPL**: You can relicense GPL-3.0 to LGPL (less restrictive), but this weakens copyleft.

3. **To AGPL-3.0**: You can relicense GPL-3.0 to AGPL-3.0 (more restrictive for web services).

4. **To permissive licenses (MIT, Apache)**: This would require permission from all contributors.

## References

- [GPL-3.0 Full Text](https://www.gnu.org/licenses/gpl-3.0.html)
- [GPL-2.0 Full Text](https://www.gnu.org/licenses/gpl-2.0.html)
- [FSF License Recommendations](https://www.gnu.org/licenses/license-recommendations.html)
- [GPL Compatibility Matrix](https://www.gnu.org/licenses/license-compatibility.html)

## Summary Table

| License | Copyleft Strength | Patent Protection | Tivoization Protection | Best For |
|---------|-------------------|-------------------|----------------------|----------|
| GPL-2.0 | Strong | Basic | No | Linux compatibility |
| **GPL-3.0** | **Strong** | **Yes** | **Yes** | **New projects** ⭐ |
| LGPL-3.0 | Weak | Yes | Yes | Libraries |
| AGPL-3.0 | Strongest | Yes | Yes | Web/SaaS services |

