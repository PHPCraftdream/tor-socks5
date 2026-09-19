//! On-disk, TTL-aware cache of resolved answers.
//!
//! Implementation lands in a follow-up task: whole-file atomic saves on
//! top of `persist-lock`, expiry decided by `resolved_at + ttl`.
