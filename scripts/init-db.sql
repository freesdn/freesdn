-- FreeSDN Database Initialization Script
-- This runs automatically when PostgreSQL container is first created

-- Enable useful extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- For fuzzy text search

-- Grant privileges (already done by POSTGRES_USER but explicit is good)
GRANT ALL PRIVILEGES ON DATABASE freesdn TO freesdn;

-- Log successful initialization
DO $$
BEGIN
    RAISE NOTICE 'FreeSDN database initialized successfully';
END $$;
