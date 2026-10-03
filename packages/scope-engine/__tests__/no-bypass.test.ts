import { describe, it, expect, vi, beforeEach } from 'vitest';
import { RequestBroker } from '../src/request-broker';
import { ScopeGuard } from '../src/scope-guard';
import { ScopeRule, ScopeGuardContext } from '../src/types';

/**
 * Mock HTTP Transport
 */
class MockTransport {
  call = vi.fn();

  async execute(): Promise<void> {
    this.call();
  }
}

describe('RequestBroker - No-Bypass Invariant', () => {
  const context: ScopeGuardContext = {
    programId: 'test-program',
    userId: 'test-user',
  };

  const allowedRules: ScopeRule[] = [
    {
      id: 'rule-1',
      ruleType: 'DOMAIN',
      value: 'allowed.com',
      inclusion: 'IN',
      isRegex: false,
      priority: 10,
    },
  ];

  let mockTransport: MockTransport;
  let guard: ScopeGuard;
  let broker: RequestBroker;

  beforeEach(() => {
    mockTransport = new MockTransport();
    guard = new ScopeGuard({ rules: allowedRules, context });
    broker = new RequestBroker({ scopeGuard: guard, transport: mockTransport });
  });

  describe('DENY → Transport NOT called', () => {
    it('should not call transport when URL is out of scope', async () => {
      const decision = guard.evaluate('https://notallowed.com');
      expect(decision.decision).toBe('DENY');

      try {
        await broker.request({
          url: 'https://notallowed.com',
          method: 'GET',
        });
      } catch {
        // Expected to throw
      }

      expect(mockTransport.call).not.toHaveBeenCalled();
    });
  });

  describe('INVALID → Transport NOT called', () => {
    it('should not call transport when URL is invalid', async () => {
      const decision = guard.evaluate('not a url');
      expect(decision.decision).toBe('INVALID');

      try {
        await broker.request({
          url: 'not a url',
          method: 'GET',
        });
      } catch {
        // Expected to throw
      }

      expect(mockTransport.call).not.toHaveBeenCalled();
    });
  });

  describe('UNKNOWN → Transport NOT called', () => {
    it('should not call transport when URL is unknown', async () => {
      // Create a guard with no rules
      const emptyGuard = new ScopeGuard({ rules: [], context });
      const emptyBroker = new RequestBroker({ scopeGuard: emptyGuard, transport: mockTransport });

      const decision = emptyGuard.evaluate('https://unknown.com');
      expect(decision.decision).toBe('UNKNOWN');

      try {
        await emptyBroker.request({
          url: 'https://unknown.com',
          method: 'GET',
        });
      } catch {
        // Expected to throw
      }

      expect(mockTransport.call).not.toHaveBeenCalled();
    });
  });

  describe('ALLOW → Transport IS called', () => {
    it('should call transport when URL is allowed', async () => {
      const decision = guard.evaluate('https://allowed.com/path');
      expect(decision.decision).toBe('ALLOW');

      try {
        await broker.request({
          url: 'https://allowed.com/path',
          method: 'GET',
        });
      } catch {
        // May throw due to mock, but transport should be called
      }

      expect(mockTransport.call).toHaveBeenCalled();
    });
  });

  describe('Request logging and audit', () => {
    it('should log request decision to audit trail', async () => {
      const auditSpy = vi.fn();
      const auditBroker = new RequestBroker({
        scopeGuard: guard,
        transport: mockTransport,
        auditLog: auditSpy,
      });

      try {
        await auditBroker.request({
          url: 'https://allowed.com',
          method: 'GET',
        });
      } catch {
        // Expected
      }

      // Verify audit was called
      expect(auditSpy).toHaveBeenCalled();
    });
  });
});
