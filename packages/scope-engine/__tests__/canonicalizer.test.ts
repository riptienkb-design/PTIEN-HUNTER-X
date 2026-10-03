import { describe, it, expect } from 'vitest';
import { Canonicalizer } from '../src/canonicalizer';

describe('Canonicalizer', () => {
  describe('Basic URL parsing', () => {
    it('should canonicalize http URL', () => {
      const result = Canonicalizer.canonicalize('http://example.com/path');
      expect(result.scheme).toBe('http');
      expect(result.hostname).toBe('example.com');
      expect(result.port).toBe(80);
      expect(result.path).toBe('/path');
    });

    it('should canonicalize https URL', () => {
      const result = Canonicalizer.canonicalize('https://example.com/path');
      expect(result.scheme).toBe('https');
      expect(result.hostname).toBe('example.com');
      expect(result.port).toBe(443);
    });

    it('should handle URL without scheme by defaulting to https', () => {
      const result = Canonicalizer.canonicalize('example.com');
      expect(result.scheme).toBe('https');
      expect(result.hostname).toBe('example.com');
    });
  });

  describe('Hostname normalization', () => {
    it('should lowercase hostname', () => {
      const result = Canonicalizer.canonicalize('https://EXAMPLE.COM');
      expect(result.hostname).toBe('example.com');
    });

    it('should remove trailing dot (FQDN notation)', () => {
      const result = Canonicalizer.canonicalize('https://example.com.');
      expect(result.hostname).toBe('example.com');
    });

    it('should remove trailing dot with subdomain', () => {
      const result = Canonicalizer.canonicalize('https://api.example.com.');
      expect(result.hostname).toBe('api.example.com');
    });

    it('should handle mixed case', () => {
      const result = Canonicalizer.canonicalize('https://Api.EXAMPLE.Com');
      expect(result.hostname).toBe('api.example.com');
    });
  });

  describe('Port normalization', () => {
    it('should default http port to 80', () => {
      const result = Canonicalizer.canonicalize('http://example.com');
      expect(result.port).toBe(80);
    });

    it('should default https port to 443', () => {
      const result = Canonicalizer.canonicalize('https://example.com');
      expect(result.port).toBe(443);
    });

    it('should preserve explicit port 80', () => {
      const result = Canonicalizer.canonicalize('http://example.com:80');
      expect(result.port).toBe(80);
    });

    it('should preserve explicit port 443', () => {
      const result = Canonicalizer.canonicalize('https://example.com:443');
      expect(result.port).toBe(443);
    });

    it('should preserve non-standard ports', () => {
      const result = Canonicalizer.canonicalize('https://example.com:8443');
      expect(result.port).toBe(8443);
    });

    it('should reject invalid port', () => {
      expect(() => Canonicalizer.canonicalize('https://example.com:99999')).toThrow();
    });
  });

  describe('Path normalization', () => {
    it('should normalize root path', () => {
      const result = Canonicalizer.canonicalize('https://example.com/');
      expect(result.path).toBe('/');
    });

    it('should normalize root path without slash', () => {
      const result = Canonicalizer.canonicalize('https://example.com');
      expect(result.path).toBe('/');
    });

    it('should preserve path', () => {
      const result = Canonicalizer.canonicalize('https://example.com/api/users');
      expect(result.path).toBe('/api/users');
    });

    it('should remove trailing slash from path', () => {
      const result = Canonicalizer.canonicalize('https://example.com/api/users/');
      expect(result.path).toBe('/api/users');
    });

    it('should normalize .. in path', () => {
      const result = Canonicalizer.canonicalize('https://example.com/a/b/../c');
      expect(result.path).toBe('/a/c');
    });

    it('should normalize . in path', () => {
      const result = Canonicalizer.canonicalize('https://example.com/a/./b');
      expect(result.path).toBe('/a/b');
    });

    it('should handle multiple .. segments', () => {
      const result = Canonicalizer.canonicalize('https://example.com/a/b/c/../../d');
      expect(result.path).toBe('/a/d');
    });

    it('should reject path traversal beyond root', () => {
      // ../../ at root should stay at root
      const result = Canonicalizer.canonicalize('https://example.com/../../a');
      expect(result.path).toBe('/a');
    });
  });

  describe('Bypass prevention', () => {
    it('should reject notexample.com as different from example.com', () => {
      const result1 = Canonicalizer.canonicalize('https://example.com');
      const result2 = Canonicalizer.canonicalize('https://notexample.com');
      expect(result1.hostname).not.toBe(result2.hostname);
    });

    it('should reject evil-example.com as different from example.com', () => {
      const result1 = Canonicalizer.canonicalize('https://example.com');
      const result2 = Canonicalizer.canonicalize('https://evil-example.com');
      expect(result1.hostname).not.toBe(result2.hostname);
    });

    it('should reject example.com.evil.test as different from example.com', () => {
      const result1 = Canonicalizer.canonicalize('https://example.com');
      const result2 = Canonicalizer.canonicalize('https://example.com.evil.test');
      expect(result1.hostname).not.toBe(result2.hostname);
    });
  });

  describe('Edge cases', () => {
    it('should reject invalid scheme', () => {
      expect(() => Canonicalizer.canonicalize('ftp://example.com')).toThrow('Invalid scheme');
    });

    it('should reject empty URL', () => {
      expect(() => Canonicalizer.canonicalize('')).toThrow();
    });

    it('should reject whitespace-only URL', () => {
      expect(() => Canonicalizer.canonicalize('   ')).toThrow();
    });

    it('should reject URL with userinfo', () => {
      expect(() => Canonicalizer.canonicalize('https://user:pass@example.com')).toThrow();
    });

    it('should handle URL with query parameters', () => {
      const result = Canonicalizer.canonicalize('https://example.com/search?q=test');
      expect(result.query).toBeDefined();
      expect(result.query?.q).toBe('test');
    });
  });

  describe('toCanonicalString', () => {
    it('should reconstruct URL without default port', () => {
      const url = Canonicalizer.canonicalize('https://example.com/path');
      const str = Canonicalizer.toCanonicalString(url);
      expect(str).toBe('https://example.com/path');
    });

    it('should include non-default port', () => {
      const url = Canonicalizer.canonicalize('https://example.com:8443/path');
      const str = Canonicalizer.toCanonicalString(url);
      expect(str).toBe('https://example.com:8443/path');
    });
  });
});
