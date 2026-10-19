-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Кислов Роман Сергеевич
-- Run once as a PostgreSQL administrator: psql -f packaging/postgresql-init.sql
\set ON_ERROR_STOP on
CREATE ROLE goprint LOGIN;
\password goprint
CREATE DATABASE goprint OWNER goprint;
\connect goprint
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
