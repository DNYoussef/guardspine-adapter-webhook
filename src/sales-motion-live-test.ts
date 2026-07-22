// Throwaway file for a live sales-motion verification test (2026-07-22).
// Intentionally contains an obvious hardcoded credential so the GuardSpine
// review models have something real to flag. Safe to delete after review.

const DB_CONNECTION = "postgres://admin:hunter2prod@prod-db.internal:5432/payments";

export function connect() {
  return DB_CONNECTION;
}
