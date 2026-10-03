import { ScopeDecision, ScopeGuardContext, ScopeGuardOptions, ScopeRule, CanonicalizedUrl } from './types';
import { Canonicalizer } from './canonicalizer';
import { HostnameValidator, PortValidator, PathValidator, SchemeValidator } from './validators';

/**
 * Scope Guard
 * Central security boundary for all network requests
 *
 * Principle: FAIL-CLOSED
 * - ALLOW: request can proceed
 * - DENY: request is blocked
 * - INVALID: URL is malformed
 * - UNKNOWN: cannot determine scope
 *
 * No request reaches transport unless decision is ALLOW
 */
export class ScopeGuard {
  private rules: ScopeRule[];
  private context: ScopeGuardContext;

  constructor(options: ScopeGuardOptions) {
    this.rules = options.rules.sort((a, b) => b.priority - a.priority);
    this.context = options.context;
  }

  /**
   * Evaluate if a URL is within scope
   * Returns structured decision with reason
   */
  evaluate(rawUrl: string): ScopeDecision {
    const timestamp = Date.now();

    // Step 1: Validate and canonicalize
    let canonical: CanonicalizedUrl;
    try {
      canonical = Canonicalizer.canonicalize(rawUrl);
    } catch (error) {
      return {
        decision: 'INVALID',
        reason: error instanceof Error ? error.message : 'Failed to canonicalize URL',
        timestamp,
      };
    }

    // Step 2: Match against scope rules
    const decision = this.matchRules(canonical);

    return {
      ...decision,
      timestamp,
    };
  }

  /**
   * Match URL against scope rules
   * Returns first matching rule result
   */
  private matchRules(canonical: CanonicalizedUrl): Omit<ScopeDecision, 'timestamp'> {
    // Check exclusions first (highest priority)
    for (const rule of this.rules.filter((r) => r.inclusion === 'EXCLUDED')) {
      if (this.ruleMatches(canonical, rule)) {
        return {
          decision: 'DENY',
          reason: 'EXCLUDED',
          ruleId: rule.id,
          details: `URL matches exclusion rule: ${rule.value}`,
        };
      }
    }

    // Check IN scope rules
    const inRules = this.rules.filter((r) => r.inclusion === 'IN');
    for (const rule of inRules) {
      if (this.ruleMatches(canonical, rule)) {
        return {
          decision: 'ALLOW',
          reason: this.determineAllowReason(rule),
          ruleId: rule.id,
          matchedValue: rule.value,
        };
      }
    }

    // Check OUT scope rules (explicit deny)
    for (const rule of this.rules.filter((r) => r.inclusion === 'OUT')) {
      if (this.ruleMatches(canonical, rule)) {
        return {
          decision: 'DENY',
          reason: 'HOST_NOT_ALLOWED',
          ruleId: rule.id,
          details: `URL does not match any IN scope rule`,
        };
      }
    }

    // No rules matched
    if (inRules.length === 0) {
      return {
        decision: 'UNKNOWN',
        reason: 'No scope rules defined for this program',
      };
    }

    // URL doesn't match any IN rule
    return {
      decision: 'DENY',
      reason: 'HOST_NOT_ALLOWED',
      details: 'URL does not match any IN scope rule',
    };
  }

  /**
   * Check if URL matches a scope rule
   */
  private ruleMatches(canonical: CanonicalizedUrl, rule: ScopeRule): boolean {
    switch (rule.ruleType) {
      case 'DOMAIN':
        return HostnameValidator.matches(canonical.hostname, rule.value, rule.isRegex);

      case 'SUBDOMAIN':
        return HostnameValidator.matches(canonical.hostname, `*.${rule.value}`, rule.isRegex);

      case 'PORT':
        const ports = rule.value.split(',').map((p) => parseInt(p.trim(), 10));
        return PortValidator.matches(canonical.port, ports);

      case 'SCHEME':
        return SchemeValidator.matches(canonical.scheme, [rule.value]);

      case 'PATH':
        return PathValidator.matches(canonical.path, [rule.value], rule.isRegex);

      default:
        return false;
    }
  }

  /**
   * Determine the specific allow reason
   */
  private determineAllowReason(
    rule: ScopeRule
  ): 'EXACT_MATCH' | 'SUBDOMAIN_MATCH' | 'IP_MATCH' | 'RANGE_MATCH' {
    switch (rule.ruleType) {
      case 'DOMAIN':
        return 'EXACT_MATCH';
      case 'SUBDOMAIN':
        return 'SUBDOMAIN_MATCH';
      default:
        return 'EXACT_MATCH';
    }
  }
}
