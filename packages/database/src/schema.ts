import { pgTable, text, varchar, integer, boolean, timestamp, jsonb, uuid, primaryKey, foreignKey, index, uniqueIndex, pgEnum } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

/**
 * ENUMS
 */
export const roleEnum = pgEnum('role', ['OWNER', 'ADMIN', 'RESEARCHER', 'VIEWER']);
export const scopeStatusEnum = pgEnum('scope_status', ['ACTIVE', 'INACTIVE', 'ARCHIVED']);
export const assetStatusEnum = pgEnum('asset_status', ['ACTIVE', 'INACTIVE', 'ARCHIVED', 'FLAGGED']);
export const assetTypeEnum = pgEnum('asset_type', ['DOMAIN', 'SUBDOMAIN', 'IP', 'URL', 'API_ENDPOINT', 'SERVICE']);
export const scopeInclusionEnum = pgEnum('scope_inclusion', ['IN', 'OUT', 'EXCLUDED']);
export const findingStatusEnum = pgEnum('finding_status', ['OBSERVED', 'CANDIDATE', 'TRIAGED', 'NEEDS_VERIFICATION', 'VERIFIED', 'REPORTED', 'ACKNOWLEDGED', 'RESOLVED', 'RETESTED', 'REJECTED', 'WONTFIX']);
export const confidenceEnum = pgEnum('confidence', ['LOW', 'MEDIUM', 'HIGH', 'CONFIRMED']);
export const severityEnum = pgEnum('severity', ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
export const jobStatusEnum = pgEnum('job_status', ['QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED', 'RETRYING']);
export const auditActionEnum = pgEnum('audit_action', ['CREATE', 'UPDATE', 'DELETE', 'SCOPE_VALIDATE', 'REQUEST_ATTEMPT', 'REQUEST_ALLOW', 'REQUEST_DENY', 'FINDING_CREATE', 'FINDING_VERIFY', 'FINDING_REPORT']);

/**
 * TABLES
 */

// Users & Auth
export const users = pgTable(
  'users',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    email: varchar('email', { length: 255 }).notNull().unique(),
    passwordHash: varchar('password_hash', { length: 255 }).notNull(),
    name: varchar('name', { length: 255 }).notNull(),
    role: roleEnum('role').notNull().default('VIEWER'),
    isActive: boolean('is_active').notNull().default(true),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    emailIdx: index('users_email_idx').on(table.email),
  })
);

// Programs (Bug Bounty Programs)
export const programs = pgTable(
  'programs',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    name: varchar('name', { length: 255 }).notNull(),
    description: text('description'),
    url: varchar('url', { length: 512 }),
    ownerId: uuid('owner_id').notNull(),
    status: scopeStatusEnum('status').notNull().default('ACTIVE'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    ownerIdIdx: index('programs_owner_id_idx').on(table.ownerId),
    fk_owner: foreignKey({
      columns: [table.ownerId],
      foreignColumns: [users.id],
    }),
  })
);

// Scope Rules (Defines what can be scanned)
export const scopeRules = pgTable(
  'scope_rules',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    programId: uuid('program_id').notNull(),
    ruleType: varchar('rule_type', { length: 50 }).notNull(), // 'DOMAIN', 'SUBDOMAIN', 'IP_RANGE', 'PATH', 'PORT', 'EXCLUSION'
    value: varchar('value', { length: 512 }).notNull(), // e.g., 'example.com', '*.example.com', '192.168.1.0/24'
    inclusion: scopeInclusionEnum('inclusion').notNull(), // 'IN', 'OUT', 'EXCLUDED'
    isRegex: boolean('is_regex').notNull().default(false),
    description: text('description'),
    priority: integer('priority').notNull().default(0), // Higher priority rules evaluated first
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    programIdIdx: index('scope_rules_program_id_idx').on(table.programId),
    fk_program: foreignKey({
      columns: [table.programId],
      foreignColumns: [programs.id],
    }),
  })
);

// Assets (Discovered targets)
export const assets = pgTable(
  'assets',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    programId: uuid('program_id').notNull(),
    type: assetTypeEnum('type').notNull(), // DOMAIN, SUBDOMAIN, IP, URL, API_ENDPOINT, SERVICE
    value: varchar('value', { length: 512 }).notNull(), // The actual asset (hostname, IP, URL, etc)
    status: assetStatusEnum('status').notNull().default('ACTIVE'),
    scope: scopeInclusionEnum('scope').notNull(), // IN, OUT, EXCLUDED - final scope decision
    rateLimit: integer('rate_limit').notNull().default(2), // requests per second
    tags: jsonb('tags').notNull().default([]), // For categorization
    metadata: jsonb('metadata'), // Free-form metadata
    lastDiscoveredAt: timestamp('last_discovered_at'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    programIdIdx: index('assets_program_id_idx').on(table.programId),
    valueIdx: index('assets_value_idx').on(table.value),
    fk_program: foreignKey({
      columns: [table.programId],
      foreignColumns: [programs.id],
    }),
    unique_asset: uniqueIndex('unique_asset_per_program').on(table.programId, table.type, table.value),
  })
);

// Asset Relationships (Graph edges)
export const assetRelationships = pgTable(
  'asset_relationships',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    programId: uuid('program_id').notNull(),
    sourceAssetId: uuid('source_asset_id').notNull(),
    targetAssetId: uuid('target_asset_id').notNull(),
    relationshipType: varchar('relationship_type', { length: 50 }).notNull(), // 'SUBDOMAIN_OF', 'HOSTED_ON', 'DEPENDS_ON', etc
    metadata: jsonb('metadata'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
  },
  (table) => ({
    programIdIdx: index('asset_relationships_program_id_idx').on(table.programId),
    sourceIdx: index('asset_relationships_source_idx').on(table.sourceAssetId),
    targetIdx: index('asset_relationships_target_idx').on(table.targetAssetId),
    fk_program: foreignKey({
      columns: [table.programId],
      foreignColumns: [programs.id],
    }),
    fk_source: foreignKey({
      columns: [table.sourceAssetId],
      foreignColumns: [assets.id],
    }),
    fk_target: foreignKey({
      columns: [table.targetAssetId],
      foreignColumns: [assets.id],
    }),
  })
);

// Domains
export const domains = pgTable(
  'domains',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    programId: uuid('program_id').notNull(),
    domain: varchar('domain', { length: 255 }).notNull(),
    registrar: varchar('registrar', { length: 255 }),
    registrationDate: timestamp('registration_date'),
    expirationDate: timestamp('expiration_date'),
    nameservers: jsonb('nameservers').notNull().default([]),
    metadata: jsonb('metadata'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    programIdIdx: index('domains_program_id_idx').on(table.programId),
    domainIdx: uniqueIndex('domains_program_domain_idx').on(table.programId, table.domain),
    fk_program: foreignKey({
      columns: [table.programId],
      foreignColumns: [programs.id],
    }),
  })
);

// Subdomains
export const subdomains = pgTable(
  'subdomains',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    programId: uuid('program_id').notNull(),
    domainId: uuid('domain_id').notNull(),
    subdomain: varchar('subdomain', { length: 255 }).notNull(),
    scope: scopeInclusionEnum('scope').notNull(), // IN, OUT, EXCLUDED
    status: assetStatusEnum('status').notNull().default('ACTIVE'),
    discoverySource: varchar('discovery_source', { length: 100 }), // 'dns', 'certificate', 'crawler', 'api', etc
    metadata: jsonb('metadata'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    programIdIdx: index('subdomains_program_id_idx').on(table.programId),
    domainIdIdx: index('subdomains_domain_id_idx').on(table.domainId),
    subdomainIdx: uniqueIndex('subdomains_program_subdomain_idx').on(table.programId, table.subdomain),
    fk_program: foreignKey({
      columns: [table.programId],
      foreignColumns: [programs.id],
    }),
    fk_domain: foreignKey({
      columns: [table.domainId],
      foreignColumns: [domains.id],
    }),
  })
);

// Services & Ports
export const services = pgTable(
  'services',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    programId: uuid('program_id').notNull(),
    assetId: uuid('asset_id').notNull(),
    port: integer('port').notNull(),
    protocol: varchar('protocol', { length: 20 }).notNull(), // 'http', 'https', 'ssh', 'ftp', etc
    service: varchar('service', { length: 100 }), // 'nginx', 'apache', 'tomcat', etc
    version: varchar('version', { length: 100 }),
    metadata: jsonb('metadata'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    programIdIdx: index('services_program_id_idx').on(table.programId),
    assetIdIdx: index('services_asset_id_idx').on(table.assetId),
    fk_program: foreignKey({
      columns: [table.programId],
      foreignColumns: [programs.id],
    }),
    fk_asset: foreignKey({
      columns: [table.assetId],
      foreignColumns: [assets.id],
    }),
  })
);

// Technologies
export const technologies = pgTable(
  'technologies',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    programId: uuid('program_id').notNull(),
    assetId: uuid('asset_id').notNull(),
    name: varchar('name', { length: 255 }).notNull(), // 'react', 'nginx', 'node.js', etc
    version: varchar('version', { length: 100 }),
    category: varchar('category', { length: 100 }).notNull(), // 'frontend', 'backend', 'server', 'database', etc
    source: varchar('source', { length: 100 }), // 'header', 'js', 'certificate', 'banner', etc
    confidence: integer('confidence').notNull().default(50), // 0-100
    metadata: jsonb('metadata'),
    discoveredAt: timestamp('discovered_at').defaultNow().notNull(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    programIdIdx: index('technologies_program_id_idx').on(table.programId),
    assetIdIdx: index('technologies_asset_id_idx').on(table.assetId),
    fk_program: foreignKey({
      columns: [table.programId],
      foreignColumns: [programs.id],
    }),
    fk_asset: foreignKey({
      columns: [table.assetId],
      foreignColumns: [assets.id],
    }),
  })
);

// Endpoints
export const endpoints = pgTable(
  'endpoints',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    programId: uuid('program_id').notNull(),
    assetId: uuid('asset_id').notNull(),
    method: varchar('method', { length: 20 }).notNull(), // GET, POST, PUT, DELETE, etc
    path: varchar('path', { length: 1024 }).notNull(),
    host: varchar('host', { length: 255 }).notNull(),
    port: integer('port'),
    scheme: varchar('scheme', { length: 20 }).notNull(), // http, https
    parameters: jsonb('parameters').notNull().default([]), // Query params, headers, body
    authRequired: boolean('auth_required').notNull().default(false),
    source: varchar('source', { length: 100 }).notNull(), // 'crawler', 'js', 'api', 'openapi', etc
    discoverySource: varchar('discovery_source', { length: 100 }),
    tags: jsonb('tags').notNull().default([]),
    metadata: jsonb('metadata'),
    firstSeenAt: timestamp('first_seen_at').defaultNow().notNull(),
    lastSeenAt: timestamp('last_seen_at').defaultNow().notNull(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    programIdIdx: index('endpoints_program_id_idx').on(table.programId),
    assetIdIdx: index('endpoints_asset_id_idx').on(table.assetId),
    pathIdx: index('endpoints_path_idx').on(table.path),
    hostIdx: index('endpoints_host_idx').on(table.host),
    fk_program: foreignKey({
      columns: [table.programId],
      foreignColumns: [programs.id],
    }),
    fk_asset: foreignKey({
      columns: [table.assetId],
      foreignColumns: [assets.id],
    }),
  })
);

// Scans
export const scans = pgTable(
  'scans',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    programId: uuid('program_id').notNull(),
    userId: uuid('user_id').notNull(),
    type: varchar('type', { length: 50 }).notNull(), // 'recon', 'deep_scan', 'api_analysis', etc
    scope: jsonb('scope').notNull(), // Snapshot of scope rules at scan time
    status: varchar('status', { length: 50 }).notNull(), // 'running', 'completed', 'failed', 'cancelled'
    startedAt: timestamp('started_at').defaultNow().notNull(),
    completedAt: timestamp('completed_at'),
    assetsDiscovered: integer('assets_discovered').notNull().default(0),
    endpointsDiscovered: integer('endpoints_discovered').notNull().default(0),
    candidatesFound: integer('candidates_found').notNull().default(0),
    metadata: jsonb('metadata'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    programIdIdx: index('scans_program_id_idx').on(table.programId),
    userIdIdx: index('scans_user_id_idx').on(table.userId),
    fk_program: foreignKey({
      columns: [table.programId],
      foreignColumns: [programs.id],
    }),
    fk_user: foreignKey({
      columns: [table.userId],
      foreignColumns: [users.id],
    }),
  })
);

// Jobs (Background work)
export const jobs = pgTable(
  'jobs',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    programId: uuid('program_id').notNull(),
    scanId: uuid('scan_id'),
    type: varchar('type', { length: 50 }).notNull(), // 'recon', 'scan', 'verify', etc
    status: jobStatusEnum('status').notNull().default('QUEUED'),
    priority: integer('priority').notNull().default(50),
    attempts: integer('attempts').notNull().default(0),
    maxAttempts: integer('max_attempts').notNull().default(3),
    payload: jsonb('payload').notNull(), // Job configuration
    result: jsonb('result'), // Job result
    error: text('error'),
    timeout: integer('timeout').notNull().default(300000), // milliseconds
    queuedAt: timestamp('queued_at').defaultNow().notNull(),
    startedAt: timestamp('started_at'),
    completedAt: timestamp('completed_at'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    programIdIdx: index('jobs_program_id_idx').on(table.programId),
    scanIdIdx: index('jobs_scan_id_idx').on(table.scanId),
    statusIdx: index('jobs_status_idx').on(table.status),
    fk_program: foreignKey({
      columns: [table.programId],
      foreignColumns: [programs.id],
    }),
    fk_scan: foreignKey({
      columns: [table.scanId],
      foreignColumns: [scans.id],
    }),
  })
);

// Findings
export const findings = pgTable(
  'findings',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    programId: uuid('program_id').notNull(),
    assetId: uuid('asset_id').notNull(),
    endpointId: uuid('endpoint_id'),
    title: varchar('title', { length: 512 }).notNull(),
    description: text('description'),
    category: varchar('category', { length: 100 }).notNull(), // 'auth', 'injection', 'config', etc
    severity: severityEnum('severity').notNull(),
    confidence: confidenceEnum('confidence').notNull(),
    status: findingStatusEnum('status').notNull().default('OBSERVED'),
    source: varchar('source', { length: 100 }), // 'scanner_name', 'manual', etc
    metadata: jsonb('metadata'),
    observedAt: timestamp('observed_at').defaultNow().notNull(),
    verifiedAt: timestamp('verified_at'),
    reportedAt: timestamp('reported_at'),
    resolvedAt: timestamp('resolved_at'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    programIdIdx: index('findings_program_id_idx').on(table.programId),
    assetIdIdx: index('findings_asset_id_idx').on(table.assetId),
    endpointIdIdx: index('findings_endpoint_id_idx').on(table.endpointId),
    statusIdx: index('findings_status_idx').on(table.status),
    fk_program: foreignKey({
      columns: [table.programId],
      foreignColumns: [programs.id],
    }),
    fk_asset: foreignKey({
      columns: [table.assetId],
      foreignColumns: [assets.id],
    }),
    fk_endpoint: foreignKey({
      columns: [table.endpointId],
      foreignColumns: [endpoints.id],
    }),
  })
);

// Evidence
export const evidence = pgTable(
  'evidence',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    findingId: uuid('finding_id').notNull(),
    type: varchar('type', { length: 50 }).notNull(), // 'request', 'response', 'screenshot', 'log', etc
    request: jsonb('request'), // HTTP request details
    response: jsonb('response'), // HTTP response details
    status: integer('status'), // HTTP status code
    headers: jsonb('headers'),
    body: text('body'),
    screenshot: varchar('screenshot', { length: 512 }), // URL to stored screenshot
    domSnapshot: text('dom_snapshot'),
    timing: jsonb('timing'), // Response time, etc
    metadata: jsonb('metadata'),
    evidenceHash: varchar('evidence_hash', { length: 64 }).notNull(), // SHA-256
    createdAt: timestamp('created_at').defaultNow().notNull(),
  },
  (table) => ({
    findingIdIdx: index('evidence_finding_id_idx').on(table.findingId),
    hashIdx: uniqueIndex('evidence_hash_idx').on(table.evidenceHash),
    fk_finding: foreignKey({
      columns: [table.findingId],
      foreignColumns: [findings.id],
    }),
  })
);

// HTTP Requests/Responses (Audit trail)
export const requests = pgTable(
  'requests',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    jobId: uuid('job_id'),
    findingId: uuid('finding_id'),
    url: varchar('url', { length: 2048 }).notNull(),
    method: varchar('method', { length: 20 }).notNull(),
    headers: jsonb('headers'),
    body: text('body'),
    timestamp: timestamp('timestamp').defaultNow().notNull(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
  },
  (table) => ({
    jobIdIdx: index('requests_job_id_idx').on(table.jobId),
    findingIdIdx: index('requests_finding_id_idx').on(table.findingId),
    fk_job: foreignKey({
      columns: [table.jobId],
      foreignColumns: [jobs.id],
    }),
    fk_finding: foreignKey({
      columns: [table.findingId],
      foreignColumns: [findings.id],
    }),
  })
);

export const responses = pgTable(
  'responses',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    requestId: uuid('request_id').notNull(),
    status: integer('status').notNull(),
    headers: jsonb('headers'),
    body: text('body'),
    size: integer('size'),
    timing: integer('timing'), // milliseconds
    timestamp: timestamp('timestamp').defaultNow().notNull(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
  },
  (table) => ({
    requestIdIdx: index('responses_request_id_idx').on(table.requestId),
    fk_request: foreignKey({
      columns: [table.requestId],
      foreignColumns: [requests.id],
    }),
  })
);

// Reports
export const reports = pgTable(
  'reports',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    programId: uuid('program_id').notNull(),
    findingIds: jsonb('finding_ids').notNull(), // Array of finding IDs included
    title: varchar('title', { length: 512 }).notNull(),
    summary: text('summary'),
    content: text('content'), // Markdown or HTML
    format: varchar('format', { length: 50 }).notNull(), // 'markdown', 'html', 'json', 'pdf'
    status: varchar('status', { length: 50 }).notNull().default('DRAFT'), // 'DRAFT', 'FINALIZED', 'SUBMITTED'
    submittedAt: timestamp('submitted_at'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    programIdIdx: index('reports_program_id_idx').on(table.programId),
    fk_program: foreignKey({
      columns: [table.programId],
      foreignColumns: [programs.id],
    }),
  })
);

// Audit Logs
export const auditLogs = pgTable(
  'audit_logs',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    programId: uuid('program_id').notNull(),
    userId: uuid('user_id'),
    action: auditActionEnum('action').notNull(),
    targetType: varchar('target_type', { length: 50 }), // 'scope_rule', 'asset', 'finding', 'request', etc
    targetId: varchar('target_id', { length: 255 }),
    details: jsonb('details'), // Structured details about the action
    decision: varchar('decision', { length: 50 }), // 'ALLOW', 'DENY', etc
    reason: text('reason'), // Why this decision was made
    metadata: jsonb('metadata'),
    ipAddress: varchar('ip_address', { length: 45 }),
    userAgent: varchar('user_agent', { length: 512 }),
    timestamp: timestamp('timestamp').defaultNow().notNull(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
  },
  (table) => ({
    programIdIdx: index('audit_logs_program_id_idx').on(table.programId),
    userIdIdx: index('audit_logs_user_id_idx').on(table.userId),
    actionIdx: index('audit_logs_action_idx').on(table.action),
    targetIdx: index('audit_logs_target_idx').on(table.targetType, table.targetId),
    fk_program: foreignKey({
      columns: [table.programId],
      foreignColumns: [programs.id],
    }),
    fk_user: foreignKey({
      columns: [table.userId],
      foreignColumns: [users.id],
    }),
  })
);

// Plugins
export const plugins = pgTable(
  'plugins',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    programId: uuid('program_id'),
    name: varchar('name', { length: 255 }).notNull(),
    version: varchar('version', { length: 50 }).notNull(),
    type: varchar('type', { length: 50 }).notNull(), // 'scanner', 'analyzer', 'reporter', etc
    isEnabled: boolean('is_enabled').notNull().default(true),
    config: jsonb('config'),
    metadata: jsonb('metadata'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    programIdIdx: index('plugins_program_id_idx').on(table.programId),
    fk_program: foreignKey({
      columns: [table.programId],
      foreignColumns: [programs.id],
    }),
  })
);

// Schedules (Continuous monitoring)
export const schedules = pgTable(
  'schedules',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    programId: uuid('program_id').notNull(),
    name: varchar('name', { length: 255 }).notNull(),
    type: varchar('type', { length: 50 }).notNull(), // 'recon', 'scan', 'verify', etc
    cronExpression: varchar('cron_expression', { length: 255 }).notNull(),
    isActive: boolean('is_active').notNull().default(true),
    lastRunAt: timestamp('last_run_at'),
    nextRunAt: timestamp('next_run_at'),
    config: jsonb('config'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    programIdIdx: index('schedules_program_id_idx').on(table.programId),
    fk_program: foreignKey({
      columns: [table.programId],
      foreignColumns: [programs.id],
    }),
  })
);

/**
 * RELATIONS (for ORM navigation)
 */

export const usersRelations = relations(users, ({ many }) => ({
  programs: many(programs),
  scans: many(scans),
  auditLogs: many(auditLogs),
}));

export const programsRelations = relations(programs, ({ one, many }) => ({
  owner: one(users, { fields: [programs.ownerId], references: [users.id] }),
  scopeRules: many(scopeRules),
  assets: many(assets),
  domains: many(domains),
  subdomains: many(subdomains),
  services: many(services),
  technologies: many(technologies),
  endpoints: many(endpoints),
  scans: many(scans),
  jobs: many(jobs),
  findings: many(findings),
  reports: many(reports),
  auditLogs: many(auditLogs),
  plugins: many(plugins),
  schedules: many(schedules),
  assetRelationships: many(assetRelationships),
}));

export const scopeRulesRelations = relations(scopeRules, ({ one }) => ({
  program: one(programs, { fields: [scopeRules.programId], references: [programs.id] }),
}));

export const assetsRelations = relations(assets, ({ one, many }) => ({
  program: one(programs, { fields: [assets.programId], references: [programs.id] }),
  services: many(services),
  technologies: many(technologies),
  endpoints: many(endpoints),
  findings: many(findings),
  sourceRelationships: many(assetRelationships, { relationName: 'sourceAsset' }),
  targetRelationships: many(assetRelationships, { relationName: 'targetAsset' }),
}));

export const assetRelationshipsRelations = relations(assetRelationships, ({ one }) => ({
  program: one(programs, { fields: [assetRelationships.programId], references: [programs.id] }),
  sourceAsset: one(assets, {
    fields: [assetRelationships.sourceAssetId],
    references: [assets.id],
    relationName: 'sourceAsset',
  }),
  targetAsset: one(assets, {
    fields: [assetRelationships.targetAssetId],
    references: [assets.id],
    relationName: 'targetAsset',
  }),
}));

export const domainsRelations = relations(domains, ({ one, many }) => ({
  program: one(programs, { fields: [domains.programId], references: [programs.id] }),
  subdomains: many(subdomains),
}));

export const subdomainsRelations = relations(subdomains, ({ one }) => ({
  program: one(programs, { fields: [subdomains.programId], references: [programs.id] }),
  domain: one(domains, { fields: [subdomains.domainId], references: [domains.id] }),
}));

export const servicesRelations = relations(services, ({ one }) => ({
  program: one(programs, { fields: [services.programId], references: [programs.id] }),
  asset: one(assets, { fields: [services.assetId], references: [assets.id] }),
}));

export const technologiesRelations = relations(technologies, ({ one }) => ({
  program: one(programs, { fields: [technologies.programId], references: [programs.id] }),
  asset: one(assets, { fields: [technologies.assetId], references: [assets.id] }),
}));

export const endpointsRelations = relations(endpoints, ({ one, many }) => ({
  program: one(programs, { fields: [endpoints.programId], references: [programs.id] }),
  asset: one(assets, { fields: [endpoints.assetId], references: [assets.id] }),
  findings: many(findings),
}));

export const scansRelations = relations(scans, ({ one, many }) => ({
  program: one(programs, { fields: [scans.programId], references: [programs.id] }),
  user: one(users, { fields: [scans.userId], references: [users.id] }),
  jobs: many(jobs),
}));

export const jobsRelations = relations(jobs, ({ one }) => ({
  program: one(programs, { fields: [jobs.programId], references: [programs.id] }),
  scan: one(scans, { fields: [jobs.scanId], references: [scans.id] }),
}));

export const findingsRelations = relations(findings, ({ one, many }) => ({
  program: one(programs, { fields: [findings.programId], references: [programs.id] }),
  asset: one(assets, { fields: [findings.assetId], references: [assets.id] }),
  endpoint: one(endpoints, { fields: [findings.endpointId], references: [endpoints.id] }),
  evidence: many(evidence),
  requests: many(requests),
}));

export const evidenceRelations = relations(evidence, ({ one }) => ({
  finding: one(findings, { fields: [evidence.findingId], references: [findings.id] }),
}));

export const requestsRelations = relations(requests, ({ one, many }) => ({
  job: one(jobs, { fields: [requests.jobId], references: [jobs.id] }),
  finding: one(findings, { fields: [requests.findingId], references: [findings.id] }),
  responses: many(responses),
}));

export const responsesRelations = relations(responses, ({ one }) => ({
  request: one(requests, { fields: [responses.requestId], references: [requests.id] }),
}));

export const reportsRelations = relations(reports, ({ one }) => ({
  program: one(programs, { fields: [reports.programId], references: [programs.id] }),
}));

export const auditLogsRelations = relations(auditLogs, ({ one }) => ({
  program: one(programs, { fields: [auditLogs.programId], references: [programs.id] }),
  user: one(users, { fields: [auditLogs.userId], references: [users.id] }),
}));

export const pluginsRelations = relations(plugins, ({ one }) => ({
  program: one(programs, { fields: [plugins.programId], references: [programs.id] }),
}));

export const schedulesRelations = relations(schedules, ({ one }) => ({
  program: one(programs, { fields: [schedules.programId], references: [programs.id] }),
}));
