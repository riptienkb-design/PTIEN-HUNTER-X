import { describe, it, expect } from 'vitest';
import { HostnameValidator, PortValidator, PathValidator, SchemeValidator } from '../src/validators';

describe('Validators', () => {
  describe('HostnameValidator', () => {
    it('should match exact hostname', () => {
      expect(HostnameValidator.matches('example.com', 'example.com')).toBe(true);
    });

    it('should match case-insensitive hostname', () => {
      expect(HostnameValidator.matches('EXAMPLE.COM', 'example.com')).toBe(true);
    });

    it('should not match different hostname', () => {
      expect(HostnameValidator.matches('notexample.com', 'example.com')).toBe(false);
    });

    it('should not match hostname with extra prefix', () => {
      expect(HostnameValidator.matches('evil-example.com', 'example.com')).toBe(false);
    });

    it('should not match hostname with extra suffix', () => {
      expect(HostnameValidator.matches('example.com.evil.test', 'example.com')).toBe(false);
    });

    it('should match subdomain with wildcard', () => {
      expect(HostnameValidator.matches('api.example.com', '*.example.com')).toBe(true);
    });

    it('should match parent domain with wildcard', () => {
      expect(HostnameValidator.matches('example.com', '*.example.com')).toBe(true);
    });

    it('should not match non-subdomain with wildcard', () => {
      expect(HostnameValidator.matches('api.other.com', '*.example.com')).toBe(false);
    });

    it('should not match hostname with extra prefix on wildcard', () => {
      expect(HostnameValidator.matches('evil-api.example.com', '*.example.com')).toBe(true);
    });
  });

  describe('HostnameValidator.preventBypass', () => {
    it('should prevent notexample.com from matching example.com', () => {
      expect(HostnameValidator.preventBypass('notexample.com', 'example.com')).toBe(false);
    });

    it('should prevent evil-example.com from matching example.com', () => {
      expect(HostnameValidator.preventBypass('evil-example.com', 'example.com')).toBe(false);
    });

    it('should prevent example.com.evil.test from matching example.com', () => {
      expect(HostnameValidator.preventBypass('example.com.evil.test', 'example.com')).toBe(false);
    });

    it('should allow exact match', () => {
      expect(HostnameValidator.preventBypass('example.com', 'example.com')).toBe(true);
    });
  });

  describe('PortValidator', () => {
    it('should validate valid ports', () => {
      expect(PortValidator.isValid(80)).toBe(true);
      expect(PortValidator.isValid(443)).toBe(true);
      expect(PortValidator.isValid(8080)).toBe(true);
    });

    it('should reject invalid ports', () => {
      expect(PortValidator.isValid(0)).toBe(false);
      expect(PortValidator.isValid(65536)).toBe(false);
      expect(PortValidator.isValid(-1)).toBe(false);
    });

    it('should match port in list', () => {
      expect(PortValidator.matches(443, [80, 443, 8080])).toBe(true);
    });

    it('should not match port not in list', () => {
      expect(PortValidator.matches(3000, [80, 443, 8080])).toBe(false);
    });
  });

  describe('PathValidator', () => {
    it('should match exact path', () => {
      expect(PathValidator.matches('/api/users', ['/api/users'])).toBe(true);
    });

    it('should match path prefix', () => {
      expect(PathValidator.matches('/api/users/123', ['/api/users'])).toBe(true);
    });

    it('should not match different path', () => {
      expect(PathValidator.matches('/admin/panel', ['/api/users'])).toBe(false);
    });

    it('should match regex path', () => {
      expect(PathValidator.matches('/api/users/123', ['/api/users/.*'], true)).toBe(true);
    });
  });

  describe('SchemeValidator', () => {
    it('should validate http scheme', () => {
      expect(SchemeValidator.isValid('http')).toBe(true);
    });

    it('should validate https scheme', () => {
      expect(SchemeValidator.isValid('https')).toBe(true);
    });

    it('should reject ftp scheme', () => {
      expect(SchemeValidator.isValid('ftp')).toBe(false);
    });

    it('should match scheme case-insensitive', () => {
      expect(SchemeValidator.matches('HTTPS', ['https'])).toBe(true);
    });
  });
});
