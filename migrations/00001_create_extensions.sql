-- 00001_create_extensions.sql
--
-- Enable required PostgreSQL extensions for StreamTrace.
--
-- timescaledb: Time-series hypertable support for high-volume event ingestion
--              and efficient time-range queries with automatic partitioning.
--
-- pgcrypto:    Provides gen_random_uuid() for UUID primary key generation
--              without application-layer dependency.
--
-- These extensions must be created by a superuser or a user with CREATE
-- privilege on the database. They are idempotent (IF NOT EXISTS).

CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
