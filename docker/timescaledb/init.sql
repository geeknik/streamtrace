-- StreamTrace - TimescaleDB initialisation
-- Runs once on first container boot (docker-entrypoint-initdb.d).

-- Core extensions required by the application
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
