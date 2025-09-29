-- user_contact--1.0.sql - Enhanced Version

-- Create the contact info table
CREATE TABLE IF NOT EXISTS user_contact_info (
    username    VARCHAR(63) PRIMARY KEY,
    email       VARCHAR(255)  NOT NULL DEFAULT ''
                  CHECK (email = '' OR email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    phone       VARCHAR(20)   NOT NULL DEFAULT ''
                  CHECK (phone = '' OR length(phone) >= 7),
    created_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CHECK (email <> '' OR phone <> '')  -- At least one must be provided
);

-- Enable Row-Level Security
ALTER TABLE user_contact_info ENABLE ROW LEVEL SECURITY;

-- Policy 1: Allow users to see their own contact info
CREATE POLICY user_own_contact_select
  ON user_contact_info
  FOR SELECT
  USING (username = current_user);

-- Policy 2: Allow users to update their own contact info
CREATE POLICY user_own_contact_update
  ON user_contact_info
  FOR UPDATE
  USING (username = current_user)
  WITH CHECK (username = current_user);

-- Policy 3: Allow users to insert their own contact info
CREATE POLICY user_own_contact_insert
  ON user_contact_info
  FOR INSERT
  WITH CHECK (username = current_user);

-- Policy 4: Allow superusers full access (bypasses RLS by default)
-- Note: Superusers bypass RLS automatically, but we create this for clarity
CREATE POLICY superuser_all_access
  ON user_contact_info
  FOR ALL
  USING (pg_has_role(current_user, 'pg_database_owner', 'MEMBER'));

-- Revoke direct table access from PUBLIC
REVOKE ALL ON TABLE user_contact_info FROM PUBLIC;

-- Grant SELECT to PUBLIC so RLS policies can work
GRANT SELECT ON TABLE user_contact_info TO PUBLIC;

-- Grant UPDATE to PUBLIC so users can update their own info via RLS
GRANT UPDATE ON TABLE user_contact_info TO PUBLIC;

-- Grant INSERT to PUBLIC so users can insert their own info via RLS
GRANT INSERT ON TABLE user_contact_info TO PUBLIC;

-- =============================================================================
-- C-LANGUAGE FUNCTIONS
-- =============================================================================

-- Set pending email and phone before CREATE USER (or update own info)
CREATE FUNCTION set_user_contact_info(email text, phone text)
RETURNS text
AS 'MODULE_PATHNAME', 'set_user_contact_info'
LANGUAGE C STRICT VOLATILE SECURITY DEFINER;

COMMENT ON FUNCTION set_user_contact_info(text, text)
IS 'Store email/phone in session for next CREATE USER call.';

-- Get contact info (users can get their own, superusers can get any)
CREATE FUNCTION get_user_contact(username text)
RETURNS record
AS 'MODULE_PATHNAME', 'get_user_contact'
LANGUAGE C STRICT STABLE SECURITY DEFINER;

COMMENT ON FUNCTION get_user_contact(text)
IS 'Return email, phone, created_at, updated_at for the given user. Users can only get their own info.';

-- Update contact info (superuser only, with upsert capability)
-- Now accepts NULL for email or phone to allow partial updates
CREATE FUNCTION update_user_contact(
    username text, 
    email text DEFAULT NULL, 
    phone text DEFAULT NULL
)
RETURNS void
AS 'MODULE_PATHNAME', 'update_user_contact'
LANGUAGE C VOLATILE SECURITY DEFINER;

COMMENT ON FUNCTION update_user_contact(text, text, text)
IS 'Superuser-only function to update or insert a user''s contact info. Either email or phone can be NULL for partial updates.';

-- NEW: Allow users to update their own contact info
CREATE FUNCTION update_my_contact_info(
    email text DEFAULT NULL,
    phone text DEFAULT NULL
)
RETURNS void
AS 'MODULE_PATHNAME', 'update_my_contact_info'
LANGUAGE C VOLATILE SECURITY DEFINER;

COMMENT ON FUNCTION update_my_contact_info(text, text)
IS 'Allow users to update their own contact information. Either email or phone can be NULL for partial updates.';

-- NEW: Direct insert function for superusers
CREATE FUNCTION insert_user_contact(username text, email text, phone text)
RETURNS void
AS 'MODULE_PATHNAME', 'insert_user_contact'
LANGUAGE C STRICT VOLATILE SECURITY DEFINER;

COMMENT ON FUNCTION insert_user_contact(text, text, text)
IS 'Superuser-only function to directly insert contact info into the table.';

-- List all user contacts (superuser only)
CREATE FUNCTION list_all_user_contacts()
RETURNS SETOF user_contact_info
AS 'MODULE_PATHNAME', 'list_all_user_contacts'
LANGUAGE C STRICT STABLE SECURITY DEFINER;

COMMENT ON FUNCTION list_all_user_contacts()
IS 'Return all rows from user_contact_info. Superuser only.';

-- Clear any pending contact info
CREATE FUNCTION clear_pending_contact_info()
RETURNS text
AS 'MODULE_PATHNAME', 'clear_pending_contact_info'
LANGUAGE C STRICT VOLATILE SECURITY DEFINER;

COMMENT ON FUNCTION clear_pending_contact_info()
IS 'Clear session-pending email and phone.';

-- =============================================================================
-- GRANT EXECUTE PERMISSIONS
-- =============================================================================

-- Grant EXECUTE on public functions
GRANT EXECUTE ON FUNCTION set_user_contact_info(text, text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION get_user_contact(text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION update_my_contact_info(text, text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION clear_pending_contact_info() TO PUBLIC;

-- Grant EXECUTE on superuser-only functions to current user (who is installing the extension)
-- This is dynamic and works for any superuser installing the extension
GRANT EXECUTE ON FUNCTION update_user_contact(text, text, text) TO current_user;
GRANT EXECUTE ON FUNCTION insert_user_contact(text, text, text) TO current_user;
GRANT EXECUTE ON FUNCTION list_all_user_contacts() TO current_user;

-- Create a view for users to see their own contact info easily
CREATE VIEW my_contact_info AS
SELECT email, phone, created_at, updated_at
FROM user_contact_info
WHERE username = current_user;

COMMENT ON VIEW my_contact_info IS 'View showing current user''s own contact information';

GRANT SELECT ON my_contact_info TO PUBLIC;