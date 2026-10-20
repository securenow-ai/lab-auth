CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY,
  email text NOT NULL UNIQUE CHECK (email = lower(email)),
  name varchar(80) NOT NULL,
  password_hash text,
  google_subject text UNIQUE,
  email_verified boolean NOT NULL DEFAULT false,
  role text NOT NULL DEFAULT 'member' CHECK (role IN ('member', 'analyst', 'admin')),
  session_version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (password_hash IS NOT NULL OR google_subject IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS sessions (
  sid varchar NOT NULL PRIMARY KEY,
  sess json NOT NULL,
  expire timestamptz NOT NULL
);
-- Store instants with their timezone so Node hosts outside UTC display the same expiry.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema=current_schema() AND table_name='sessions'
      AND column_name='expire' AND data_type='timestamp without time zone'
  ) THEN
    ALTER TABLE sessions ALTER COLUMN expire TYPE timestamptz USING expire AT TIME ZONE 'UTC';
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS sessions_expire_idx ON sessions (expire);

CREATE TABLE IF NOT EXISTS security_events (
  id bigserial PRIMARY KEY,
  type varchar(80) NOT NULL,
  outcome varchar(20) NOT NULL CHECK (outcome IN ('success', 'failure', 'blocked')),
  actor_id uuid REFERENCES users(id) ON DELETE SET NULL,
  ip_hash varchar(64),
  request_id uuid,
  metadata jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS security_events_created_idx ON security_events (created_at DESC);

CREATE TABLE IF NOT EXISTS rate_buckets (
  key varchar(100) NOT NULL,
  window_start bigint NOT NULL,
  count integer NOT NULL DEFAULT 1,
  PRIMARY KEY (key, window_start)
);
ALTER TABLE rate_buckets ALTER COLUMN key TYPE varchar(100);

-- A per-user object with a PREDICTABLE integer key, so IDOR hunting (scan / walk / dump) is realistic.
CREATE TABLE IF NOT EXISTS notes (
  id serial PRIMARY KEY,
  owner_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title varchar(120) NOT NULL,
  body text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS notes_owner_idx ON notes (owner_id);
