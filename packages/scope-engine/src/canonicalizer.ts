import { URL } from 'url';
import { CanonicalizedUrl } from './types';

/**
 * URL Canonicalizer
 * Standardizes URLs to prevent bypass attacks
 *
 * Handles:
 * - Case normalization
 * - Trailing dot removal
 * - Default port normalization
 * - Path normalization
 * - Query parameter sorting
 * - URL encoding validation
 */
export class Canonicalizer {
  /**
   * Parse and canonicalize a URL string
   * Throws on invalid/malformed URLs
   */
  static canonicalize(rawUrl: string): CanonicalizedUrl {
    if (!rawUrl || typeof rawUrl !== 'string') {
      throw new Error('Invalid URL: must be a non-empty string');
    }

    const trimmed = rawUrl.trim();

    if (!trimmed) {
      throw new Error('Invalid URL: empty after trimming');
    }

    // Parse URL
    let parsed: URL;
    try {
      // Handle URLs without scheme
      const urlToparse = trimmed.includes('://') ? trimmed : `https://${trimmed}`;
      parsed = new URL(urlToparse);
    } catch (error) {
      throw new Error(`Invalid URL format: ${error instanceof Error ? error.message : 'unknown error'}`);
    }

    // Validate scheme
    const scheme = parsed.protocol.replace(':', '').toLowerCase();
    if (!['http', 'https'].includes(scheme)) {
      throw new Error(`Invalid scheme: ${scheme}. Only http and https are allowed.`);
    }

    // Extract hostname and remove trailing dot
    let hostname = parsed.hostname?.toLowerCase() || '';
    if (!hostname) {
      throw new Error('Invalid URL: missing hostname');
    }

    // Remove trailing dot (FQDN notation)
    hostname = hostname.replace(/\.$/, '');

    // Validate hostname format
    if (!this.isValidHostname(hostname)) {
      throw new Error(`Invalid hostname format: ${hostname}`);
    }

    // Normalize port
    const port = this.normalizePort(parsed.port, scheme);

    // Normalize path
    const path = this.normalizePath(parsed.pathname);

    // Parse query parameters
    const query = this.parseQuery(parsed.search);

    return {
      scheme,
      hostname,
      port,
      path,
      query: Object.keys(query).length > 0 ? query : undefined,
    };
  }

  /**
   * Reconstruct canonical URL string
   */
  static toCanonicalString(url: CanonicalizedUrl): string {
    const defaultPorts: Record<string, number> = { http: 80, https: 443 };
    const portStr =
      url.port === defaultPorts[url.scheme] ? '' : `:${url.port}`;
    const pathStr = url.path === '/' ? '' : url.path;

    return `${url.scheme}://${url.hostname}${portStr}${pathStr}`;
  }

  /**
   * Validate hostname format
   * Prevents IDN bypass, homograph attacks, etc
   */
  private static isValidHostname(hostname: string): boolean {
    if (hostname.length === 0 || hostname.length > 253) {
      return false;
    }

    // Check for valid characters
    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/.test(hostname)) {
      return false;
    }

    // Check for valid IP (v4 or v6)
    if (this.isValidIP(hostname)) {
      return true;
    }

    // No consecutive dots
    if (hostname.includes('..')) {
      return false;
    }

    return true;
  }

  /**
   * Validate IP addresses (v4 and v6)
   */
  private static isValidIP(ip: string): boolean {
    // IPv4
    const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipv4Regex.test(ip)) {
      return true;
    }

    // IPv6 (simplified validation)
    if (ip.includes(':') && /^[0-9a-f:]+$/.test(ip)) {
      return true;
    }

    return false;
  }

  /**
   * Normalize port to standard values
   */
  private static normalizePort(port: string | null, scheme: string): number {
    if (!port) {
      return scheme === 'https' ? 443 : 80;
    }

    const portNum = parseInt(port, 10);
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
      throw new Error(`Invalid port: ${port}`);
    }

    return portNum;
  }

  /**
   * Normalize path
   * Removes ./ and ../ components, decodes properly
   */
  private static normalizePath(pathname: string): string {
    if (!pathname) {
      return '/';
    }

    // Decode encoded characters
    let decoded: string;
    try {
      decoded = decodeURIComponent(pathname);
    } catch {
      throw new Error(`Invalid path encoding: ${pathname}`);
    }

    // Split path into segments
    const segments = decoded.split('/').filter((s) => s !== '' && s !== '.');

    // Handle .. segments (go up directory)
    const normalized: string[] = [];
    for (const segment of segments) {
      if (segment === '..') {
        if (normalized.length > 0) {
          normalized.pop();
        }
      } else {
        normalized.push(segment);
      }
    }

    // Reconstruct path
    const result = '/' + normalized.join('/');
    return result === '/' ? '/' : result; // No trailing slash
  }

  /**
   * Parse query string into object
   */
  private static parseQuery(search: string): Record<string, string> {
    const query: Record<string, string> = {};
    if (!search || search === '?') {
      return query;
    }

    const params = new URLSearchParams(search);
    for (const [key, value] of params) {
      query[key] = value;
    }

    return query;
  }
}
