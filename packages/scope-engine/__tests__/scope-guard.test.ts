import { describe, it, expect, beforeEach } from 'vitest';
import { ScopeGuard } from '../src/scope-guard';
import { ScopeRule, ScopeGuardContext } from '../src/types';

describe('ScopeGuard - Fail-Closed Principle', () => {
  const context: ScopeGuardContext = {
    programId: 'test-program',
    userId: 'test-user',
  };

  describe('UNKNOWN → DENY', () => {
    it('should return UNKNOWN when no scope rules are defined', () => {
      const guard = new ScopeGuard({
        rules: [],
        context,
      });

      const decision = guard.evaluate('https://example.com');
      expect(decision.decision).toBe('UNKNOWN');
      expect(decision.reason).toBe('No scope rules defined for this program');
    });

    it('should return DENY when URL does not match any IN scope rule', () => {
      const rules: ScopeRule[] = [
        {
          id: 'rule-1',
          ruleType: 'DOMAIN',
          value: 'allowed.com',
          inclusion: 'IN',
          isRegex: false,
          priority: 10,
        },
      ];

      const guard = new ScopeGuard({ rules, context });
      const decision = guard.evaluate('https://notallowed.com');
      expect(decision.decision).toBe('DENY');
      expect(decision.reason).toBe('HOST_NOT_ALLOWED');
    });
  });

  describe('INVALID → DENY', () => {
    it('should return INVALID for malformed URL', () => {
      const guard = new ScopeGuard({
        rules: [],
        context,
      });

      const decision = guard.evaluate('not a url');
      expect(decision.decision).toBe('INVALID');
    });

    it('should return INVALID for invalid scheme', () => {
      const guard = new ScopeGuard({
        rules: [],
        context,
      });

      const decision = guard.evaluate('ftp://example.com');
      expect(decision.decision).toBe('INVALID');
    });

    it('should return INVALID for URL with userinfo', () => {
      const guard = new ScopeGuard({
        rules: [],
        context,
      });

      const decision = guard.evaluate('https://user:pass@example.com');
      expect(decision.decision).toBe('INVALID');
    });
  });

  describe('OUT_OF_SCOPE → DENY', () => {
    it('should return DENY for excluded domain', () => {
      const rules: ScopeRule[] = [
        {
          id: 'rule-1',
          ruleType: 'DOMAIN',
          value: 'example.com',
          inclusion: 'EXCLUDED',
          isRegex: false,
          priority: 20,
        },
        {
          id: 'rule-2',
          ruleType: 'DOMAIN',
          value: 'example.com',
          inclusion: 'IN',
          isRegex: false,
          priority: 10,
        },
      ];

      const guard = new ScopeGuard({ rules, context });
      const decision = guard.evaluate('https://example.com');
      expect(decision.decision).toBe('DENY');
      expect(decision.reason).toBe('EXCLUDED');
    });
  });

  describe('ALLOW → PROCEED', () => {
    it('should return ALLOW for exact hostname match', () => {
      const rules: ScopeRule[] = [
        {
          id: 'rule-1',
          ruleType: 'DOMAIN',
          value: 'example.com',
          inclusion: 'IN',
          isRegex: false,
          priority: 10,
        },
      ];

      const guard = new ScopeGuard({ rules, context });
      const decision = guard.evaluate('https://example.com');
      expect(decision.decision).toBe('ALLOW');
      expect(decision.reason).toBe('EXACT_MATCH');
    });

    it('should return ALLOW for subdomain match', () => {
      const rules: ScopeRule[] = [
        {
          id: 'rule-1',
          ruleType: 'DOMAIN',
          value: '*.example.com',
          inclusion: 'IN',
          isRegex: false,
          priority: 10,
        },
      ];

      const guard = new ScopeGuard({ rules, context });
      const decision = guard.evaluate('https://api.example.com');
      expect(decision.decision).toBe('ALLOW');
      expect(decision.reason).toBe('SUBDOMAIN_MATCH');
    });
  });

  describe('Bypass Prevention', () => {
    it('should not allow notexample.com when example.com is in scope', () => {
      const rules: ScopeRule[] = [
        {
          id: 'rule-1',
          ruleType: 'DOMAIN',
          value: 'example.com',
          inclusion: 'IN',
          isRegex: false,
          priority: 10,
        },
      ];

      const guard = new ScopeGuard({ rules, context });
      const decision = guard.evaluate('https://notexample.com');
      expect(decision.decision).toBe('DENY');
    });

    it('should not allow evil-example.com when example.com is in scope', () => {
      const rules: ScopeRule[] = [
        {
          id: 'rule-1',
          ruleType: 'DOMAIN',
          value: 'example.com',
          inclusion: 'IN',
          isRegex: false,
          priority: 10,
        },
      ];

      const guard = new ScopeGuard({ rules, context });
      const decision = guard.evaluate('https://evil-example.com');
      expect(decision.decision).toBe('DENY');
    });

    it('should not allow example.com.evil.test when example.com is in scope', () => {
      const rules: ScopeRule[] = [
        {
          id: 'rule-1',
          ruleType: 'DOMAIN',
          value: 'example.com',
          inclusion: 'IN',
          isRegex: false,
          priority: 10,
        },
      ];

      const guard = new ScopeGuard({ rules, context });
      const decision = guard.evaluate('https://example.com.evil.test');
      expect(decision.decision).toBe('DENY');
    });
  });
});
