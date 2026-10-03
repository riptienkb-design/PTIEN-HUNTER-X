import { Canonicalizer } from './canonicalizer';

/**
 * Hostname Validator
 * Validates hostname against scope rules
 */
export class HostnameValidator {
  /**
   * Check if hostname matches allowed hostname
   * Supports exact match and subdomain match
   */
  static matches(hostname: string, allowed: string, isRegex: boolean = false): boolean {
    const normalizedHostname = hostname.toLowerCase();
    const normalizedAllowed = allowed.toLowerCase().replace(/\.$/, '');

    // Regex match
    if (isRegex) {
      try {
        const regex = new RegExp(`^${normalizedAllowed}$`, 'i');
        return regex.test(normalizedHostname);
      } catch {
        return false;
      }
    }

    // Exact match
    if (normalizedHostname === normalizedAllowed) {
      return true;
    }

    // Subdomain match (*.example.com matches api.example.com but not notexample.com)
    if (normalizedAllowed.startsWith('*.')) {
      const domain = normalizedAllowed.slice(2); // Remove *.
      if (normalizedHostname === domain) {
        return true; // *.example.com should match example.com
      }
      if (normalizedHostname.endsWith(`.${domain}`)) {
        return true; // *.example.com matches api.example.com
      }
    }

    return false;
  }

  /**
   * Validate hostname against list of rules
   */
  static validate(hostname: string, allowedHostnames: Array<{ value: string; isRegex: boolean }>): boolean {
    return allowedHostnames.some((rule) => this.matches(hostname, rule.value, rule.isRegex));
  }

  /**
   * Prevent common bypass patterns
   */
  static preventBypass(hostname: string, allowedPattern: string): boolean {
    const norm = hostname.toLowerCase();
    const pattern = allowedPattern.toLowerCase().replace(/\.$/, '');

    // Prevent: notexample.com matching example.com
    if (!this.matches(hostname, allowedPattern)) {
      return false;
    }

    // Prevent: example.com.attacker.com
    if (pattern.includes('.')) {
      const parts = norm.split('.');
      const patternParts = pattern.split('.');

      if (parts.length < patternParts.length) {
        return false;
      }

      // Check that pattern parts match at the end
      for (let i = 0; i < patternParts.length; i++) {
        const patIdx = patternParts.length - 1 - i;
        const partIdx = parts.length - 1 - i;
        if (parts[partIdx] !== patternParts[patIdx] && patternParts[patIdx] !== '*') {
          return false;
        }
      }
    }

    return true;
  }
}

/**
 * Port Validator
 */
export class PortValidator {
  static isValid(port: number): boolean {
    return port >= 1 && port <= 65535;
  }

  static matches(port: number, allowedPorts: number[]): boolean {
    return allowedPorts.includes(port);
  }
}

/**
 * Path Validator
 */
export class PathValidator {
  static matches(path: string, allowedPaths: string[], isRegex: boolean = false): boolean {
    for (const allowedPath of allowedPaths) {
      if (isRegex) {
        try {
          const regex = new RegExp(`^${allowedPath}`, 'i');
          if (regex.test(path)) {
            return true;
          }
        } catch {
          continue;
        }
      } else {
        if (path === allowedPath || path.startsWith(allowedPath + '/')) {
          return true;
        }
      }
    }
    return false;
  }
}

/**
 * Scheme Validator
 */
export class SchemeValidator {
  static isValid(scheme: string): boolean {
    return ['http', 'https'].includes(scheme.toLowerCase());
  }

  static matches(scheme: string, allowedSchemes: string[]): boolean {
    return allowedSchemes.some((s) => s.toLowerCase() === scheme.toLowerCase());
  }
}
