#!/usr/bin/env node
/**
 * build-reasoningbank.mjs
 * -----------------------
 * Reproducible builder for the ReasoningBank AgentDB store.
 *
 * The store itself (~/.agentdb/reasoningbank.db) is intentionally gitignored
 * by the repo-wide `*.db` rule — databases are local state. THIS script is the
 * committed source of truth: run it on any machine to regenerate an identical
 * empty store.
 *
 *   node ~/.agentdb/build-reasoningbank.mjs
 *
 * Config: 384-dim vectors (Xenova/all-MiniLM-L6-v2), ruvector backend — matching
 * ~/.claude-flow/embeddings.json. NOTE: 384, not the reasoningbank-agentdb skill's
 * stale 1536 default; a mismatch makes the HNSW index reject every insert.
 *
 * Requires Node >= 22 (built-in node:sqlite). No npm install needed.
 */
import { DatabaseSync } from "node:sqlite";
import { mkdirSync, existsSync, copyFileSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const DB_DIR = join(homedir(), ".agentdb");
const DB_PATH = join(DB_DIR, "reasoningbank.db");

// AgentDB CLI compatibility config (mirrors what `agentdb init` writes).
const CONFIG = [
  ["backend", "ruvector"],
  ["dimension", "384"],
  ["embedding_model", "Xenova/all-MiniLM-L6-v2"],
  ["version", "2.0.0"],
];
// Fixed timestamp so rebuilds are deterministic (no Date.now()).
const SEED_TS = 1783636513;

// Canonical RuFlo V3 ReasoningBank schema (384-dim). Kept inline so this script
// is fully self-contained and does not depend on ~/.swarm/schema.sql persisting.
const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS memory_entries (
  id TEXT PRIMARY KEY,
  key TEXT NOT NULL,
  namespace TEXT DEFAULT 'default',
  content TEXT NOT NULL,
  type TEXT DEFAULT 'semantic' CHECK(type IN ('semantic', 'episodic', 'procedural', 'working', 'pattern')),
  embedding TEXT,
  embedding_model TEXT DEFAULT 'local',
  embedding_dimensions INTEGER,
  tags TEXT,
  metadata TEXT,
  owner_id TEXT,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
  expires_at INTEGER,
  last_accessed_at INTEGER,
  access_count INTEGER DEFAULT 0,
  status TEXT DEFAULT 'active' CHECK(status IN ('active', 'archived', 'deleted')),
  UNIQUE(namespace, key)
);
CREATE INDEX IF NOT EXISTS idx_memory_namespace ON memory_entries(namespace);
CREATE INDEX IF NOT EXISTS idx_memory_key ON memory_entries(key);
CREATE INDEX IF NOT EXISTS idx_memory_type ON memory_entries(type);
CREATE INDEX IF NOT EXISTS idx_memory_status ON memory_entries(status);
CREATE INDEX IF NOT EXISTS idx_memory_created ON memory_entries(created_at);
CREATE INDEX IF NOT EXISTS idx_memory_accessed ON memory_entries(last_accessed_at);
CREATE INDEX IF NOT EXISTS idx_memory_owner ON memory_entries(owner_id);

CREATE TABLE IF NOT EXISTS patterns (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  pattern_type TEXT NOT NULL CHECK(pattern_type IN (
    'task-routing', 'error-recovery', 'optimization', 'learning',
    'coordination', 'prediction', 'code-pattern', 'workflow'
  )),
  condition TEXT NOT NULL,
  action TEXT NOT NULL,
  description TEXT,
  confidence REAL DEFAULT 0.5,
  success_count INTEGER DEFAULT 0,
  failure_count INTEGER DEFAULT 0,
  decay_rate REAL DEFAULT 0.01,
  half_life_days INTEGER DEFAULT 30,
  embedding TEXT,
  embedding_dimensions INTEGER,
  version INTEGER DEFAULT 1,
  parent_id TEXT REFERENCES patterns(id),
  tags TEXT,
  metadata TEXT,
  source TEXT,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
  last_matched_at INTEGER,
  last_success_at INTEGER,
  last_failure_at INTEGER,
  status TEXT DEFAULT 'active' CHECK(status IN ('active', 'archived', 'deprecated', 'experimental'))
);
CREATE INDEX IF NOT EXISTS idx_patterns_type ON patterns(pattern_type);
CREATE INDEX IF NOT EXISTS idx_patterns_confidence ON patterns(confidence DESC);
CREATE INDEX IF NOT EXISTS idx_patterns_status ON patterns(status);
CREATE INDEX IF NOT EXISTS idx_patterns_last_matched ON patterns(last_matched_at);

CREATE TABLE IF NOT EXISTS pattern_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern_id TEXT NOT NULL REFERENCES patterns(id),
  version INTEGER NOT NULL,
  confidence REAL,
  success_count INTEGER,
  failure_count INTEGER,
  condition TEXT,
  action TEXT,
  change_type TEXT CHECK(change_type IN ('created', 'updated', 'success', 'failure', 'decay', 'merged', 'split')),
  change_reason TEXT,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);
CREATE INDEX IF NOT EXISTS idx_pattern_history_pattern ON pattern_history(pattern_id);

CREATE TABLE IF NOT EXISTS trajectories (
  id TEXT PRIMARY KEY,
  session_id TEXT,
  status TEXT DEFAULT 'active' CHECK(status IN ('active', 'completed', 'failed', 'abandoned')),
  verdict TEXT CHECK(verdict IN ('success', 'failure', 'partial', NULL)),
  task TEXT,
  context TEXT,
  total_steps INTEGER DEFAULT 0,
  total_reward REAL DEFAULT 0,
  started_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
  ended_at INTEGER,
  extracted_pattern_id TEXT REFERENCES patterns(id)
);

CREATE TABLE IF NOT EXISTS trajectory_steps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  trajectory_id TEXT NOT NULL REFERENCES trajectories(id),
  step_number INTEGER NOT NULL,
  action TEXT NOT NULL,
  observation TEXT,
  reward REAL DEFAULT 0,
  metadata TEXT,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);
CREATE INDEX IF NOT EXISTS idx_steps_trajectory ON trajectory_steps(trajectory_id);

CREATE TABLE IF NOT EXISTS migration_state (
  id TEXT PRIMARY KEY,
  migration_type TEXT NOT NULL,
  status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'in_progress', 'completed', 'failed', 'rolled_back')),
  total_items INTEGER DEFAULT 0,
  processed_items INTEGER DEFAULT 0,
  failed_items INTEGER DEFAULT 0,
  skipped_items INTEGER DEFAULT 0,
  current_batch INTEGER DEFAULT 0,
  last_processed_id TEXT,
  source_path TEXT,
  source_type TEXT,
  destination_path TEXT,
  backup_path TEXT,
  backup_created_at INTEGER,
  last_error TEXT,
  errors TEXT,
  started_at INTEGER,
  completed_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  state TEXT NOT NULL,
  status TEXT DEFAULT 'active' CHECK(status IN ('active', 'paused', 'completed', 'expired')),
  project_path TEXT,
  branch TEXT,
  tasks_completed INTEGER DEFAULT 0,
  patterns_learned INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
  expires_at INTEGER
);

CREATE TABLE IF NOT EXISTS vector_indexes (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  dimensions INTEGER NOT NULL,
  metric TEXT DEFAULT 'cosine' CHECK(metric IN ('cosine', 'euclidean', 'dot')),
  hnsw_m INTEGER DEFAULT 16,
  hnsw_ef_construction INTEGER DEFAULT 200,
  hnsw_ef_search INTEGER DEFAULT 100,
  quantization_type TEXT CHECK(quantization_type IN ('none', 'scalar', 'product')),
  quantization_bits INTEGER DEFAULT 8,
  total_vectors INTEGER DEFAULT 0,
  last_rebuild_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);

CREATE TABLE IF NOT EXISTS graph_edges (
  id              TEXT PRIMARY KEY,
  source_id       TEXT NOT NULL,
  target_id       TEXT NOT NULL,
  relation        TEXT NOT NULL,
  weight          REAL DEFAULT 1.0,
  confidence      REAL DEFAULT 1.0,
  decay_rate      REAL DEFAULT 0.0,
  last_reinforced TEXT,
  witness_id      TEXT,
  embedding_ref   TEXT,
  metadata        TEXT,
  created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_graph_edges_source    ON graph_edges (source_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_target    ON graph_edges (target_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_relation  ON graph_edges (relation);
CREATE INDEX IF NOT EXISTS idx_graph_edges_reinforced ON graph_edges (last_reinforced);

CREATE TABLE IF NOT EXISTS metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER DEFAULT (strftime('%s', 'now') * 1000)
);

INSERT OR REPLACE INTO metadata (key, value) VALUES
  ('schema_version', '3.0.0'),
  ('backend', 'hybrid'),
  ('sql_js', 'true'),
  ('vector_embeddings', 'enabled'),
  ('pattern_learning', 'enabled'),
  ('temporal_decay', 'enabled'),
  ('hnsw_indexing', 'enabled');

-- 384-dim default indexes (Xenova/all-MiniLM-L6-v2). HNSW rejects inserts whose
-- dim does not match these rows, so this MUST stay 384.
INSERT OR IGNORE INTO vector_indexes (id, name, dimensions) VALUES
  ('default', 'default', 384),
  ('patterns', 'patterns', 384);
`;

function main() {
  mkdirSync(DB_DIR, { recursive: true });

  if (existsSync(DB_PATH)) {
    // Fail-safe policy: a rebuild must NEVER silently clobber a store that may
    // hold live learning data. Abort by default; only proceed under --force, and
    // even then back the existing store up first so nothing is ever lost.
    if (!process.argv.includes("--force")) {
      console.error(`Refusing to rebuild: ${DB_PATH} already exists.`);
      console.error("It may hold live learning data (patterns/trajectories).");
      console.error(
        "Re-run with --force to back it up and rebuild, or delete the file first.",
      );
      process.exitCode = 1;
      return;
    }
    // --force: preserve the existing store, then clear it (and any WAL/SHM
    // sidecars) so DatabaseSync opens a clean, fully-rebuilt database.
    const backup = `${DB_PATH}.bak-${Date.now()}`;
    copyFileSync(DB_PATH, backup);
    for (const f of [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`]) {
      if (existsSync(f)) rmSync(f);
    }
    console.log(
      `--force: backed up existing store to ${backup}, rebuilding fresh.`,
    );
  }

  const db = new DatabaseSync(DB_PATH);
  db.exec(SCHEMA);

  db.exec(
    `CREATE TABLE IF NOT EXISTS agentdb_config (key TEXT PRIMARY KEY, value TEXT, updated_at INTEGER);`,
  );
  const cfg = db.prepare(
    `INSERT OR REPLACE INTO agentdb_config(key,value,updated_at) VALUES(?,?,?)`,
  );
  for (const [k, v] of CONFIG) cfg.run(k, v, SEED_TS);

  db.exec("PRAGMA wal_checkpoint(TRUNCATE)");

  const tables = db
    .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    .all()
    .map((r) => r.name);
  const dim = db
    .prepare("SELECT dimensions FROM vector_indexes WHERE id='default'")
    .get().dimensions;
  db.close();

  console.log(`Built ${DB_PATH}`);
  console.log(`  tables: ${tables.length} -> ${tables.join(", ")}`);
  console.log(`  vector dimension: ${dim}`);
  if (dim !== 384) throw new Error(`FATAL: expected 384-dim index, got ${dim}`);
}

main();
