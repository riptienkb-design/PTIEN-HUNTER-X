/**
 * Scope Guard Types
 * Defines the contract for scope evaluation
 */

export type ScopeDecisionType = 'ALLOW' | 'DENY' | 'INVALID' | 'UNKNOWN';

export type ScopeAllowReason = 'EXACT_MATCH' | 'SUBDOMAIN_MATCH' | 'IP_MATCH' | 'RANGE_MATCH';

export type ScopeDenyReason =
  | 'EXCLUDED'
  | 'HOST_NOT_ALLOWED'
  | 'PORT_NOT_ALLOWED'
  | 'PATH_NOT_ALLOWED'
  | 'SCHEME_NOT_ALLOWED'
  | 'AUTHORIZATION_REQUIRED'
  | 'POLICY_DENIED'
  | 'RATE_LIMIT_EXCEEDED';

export type ScopeDecision =
  | {
      decision: 'ALLOW';
      reason: ScopeAllowReason;
      ruleId: string;
      matchedValue: string;
      timestamp: number;
    }
  | {
      decision: 'DENY';
      reason: ScopeDenyReason;
      ruleId?: string;
      details?: string;
      timestamp: number;
    }
  | {
      decision: 'INVALID';
      reason: string;
      timestamp: number;
    }
  | {
      decision: 'UNKNOWN';
      reason: string;
      timestamp: number;
    };

export interface CanonicalizedUrl {
  scheme: string; // 'http' | 'https'
  hostname: string; // lowercase, no trailing dot
  port: number; // normalized to default if omitted
  path: string; // normalized, no trailing slash unless root
  query?: Record<string, string>;
}

export interface ScopeRule {
  id: string;
  ruleType: 'DOMAIN' | 'SUBDOMAIN' | 'IP_RANGE' | 'PATH' | 'PORT' | 'SCHEME' | 'EXCLUSION';
  value: string;
  inclusion: 'IN' | 'OUT' | 'EXCLUDED';
  isRegex: boolean;
  priority: number;
}

export interface ScopeGuardContext {
  programId: string;
  userId?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface ScopeGuardOptions {
  rules: ScopeRule[];
  context: ScopeGuardContext;
}

export interface RequestBrokerContext {
  scopeGuard: ScopeDecision;
  rateLimit?: {
    maxRequests: number;
    windowMs: number;
  };
  concurrency?: {
    maxConcurrent: number;
  };
  timeout?: number;
  audit?: boolean;
}

export interface RequestBrokerOptions {
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS';
  headers?: Record<string, string>;
  body?: string | Buffer;
  timeout?: number;
  retries?: number;
  context: RequestBrokerContext;
}

export interface HttpTransportOptions {
  url: string;
  method: string;
  headers?: Record<string, string>;
  body?: string | Buffer;
  timeout: number;
  signal?: AbortSignal;
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
  timing: number; // ms
}
