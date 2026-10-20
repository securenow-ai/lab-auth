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

-- Collaboration surface (threat model 02-authorization, Category O: teams / invites / membership).
-- An org groups members; membership carries a per-org role; invites bind a role to a specific
-- invited email with a single-use, expiring token. This is the modern-SaaS authorization surface.
CREATE TABLE IF NOT EXISTS orgs (
  id uuid PRIMARY KEY,
  name varchar(80) NOT NULL,
  created_by uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS org_members (
  org_id uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role text NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, user_id)
);
CREATE INDEX IF NOT EXISTS org_members_user_idx ON org_members (user_id);

-- An invite is bound to the invited EMAIL (identity) and a role capped at creation. The token is a
-- random uuid; single-use is enforced by the status transition pending -> accepted.
CREATE TABLE IF NOT EXISTS org_invites (
  token uuid PRIMARY KEY,
  org_id uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  email text NOT NULL CHECK (email = lower(email)),
  role text NOT NULL CHECK (role IN ('admin', 'member')),
  invited_by uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'revoked')),
  accepted_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL DEFAULT now() + interval '7 days'
);
CREATE INDEX IF NOT EXISTS org_invites_org_idx ON org_invites (org_id);
CREATE INDEX IF NOT EXISTS org_invites_email_idx ON org_invites (email);
