-- user_contact--1.0.sql

CREATE TABLE IF NOT EXISTS user_contact_info (
    username    VARCHAR(63) PRIMARY KEY,
    email       VARCHAR(255)  NOT NULL
                  CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    phone       VARCHAR(20)   NOT NULL
                  CHECK (length(phone) >= 7),
    created_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- Revoke all direct privileges on the base table
REVOKE ALL ON TABLE user_contact_info FROM PUBLIC;
REVOKE ALL ON TABLE user_contact_info FROM postgres;
REVOKE ALL ON TABLE user_contact_info FROM current_user;

-- 3. Enable Row-Level Security
ALTER TABLE user_contact_info ENABLE ROW LEVEL SECURITY;

--  Deny all direct access via RLS policy
CREATE POLICY no_direct_access
  ON user_contact_info
  FOR ALL
  USING (false)
  WITH CHECK (false);

-- Expose the C-language API functions

-- Set pending email and phone before CREATE USER
CREATE FUNCTION set_user_contact_info(email text, phone text)
RETURNS text
AS 'MODULE_PATHNAME', 'set_user_contact_info'
LANGUAGE C STRICT VOLATILE SECURITY DEFINER;
COMMENT ON FUNCTION set_user_contact_info(text, text)
IS 'Store email/phone in session for next CREATE USER call.';


CREATE FUNCTION get_user_contact(username text)
RETURNS record
AS 'MODULE_PATHNAME', 'get_user_contact'
LANGUAGE C STRICT STABLE SECURITY DEFINER;
COMMENT ON FUNCTION get_user_contact(text)
IS 'Return email, phone, created_at, updated_at for the given user.';

-- Update contact info (superuser only)
CREATE FUNCTION update_user_contact(username text, email text, phone text)
RETURNS void
AS 'MODULE_PATHNAME', 'update_user_contact'
LANGUAGE C STRICT VOLATILE;
COMMENT ON FUNCTION update_user_contact(text, text, text)
IS 'Superuser-only function to update a user''s contact info.';

-- List all user contacts (superuser only)
CREATE FUNCTION list_all_user_contacts()
RETURNS SETOF user_contact_info
AS 'MODULE_PATHNAME', 'list_all_user_contacts'
LANGUAGE C STRICT STABLE;
COMMENT ON FUNCTION list_all_user_contacts()
IS 'Return all rows from user_contact_info.';

-- Clear any pending contact info
CREATE FUNCTION clear_pending_contact_info()
RETURNS text
AS 'MODULE_PATHNAME', 'clear_pending_contact_info'
LANGUAGE C STRICT VOLATILE SECURITY DEFINER;
COMMENT ON FUNCTION clear_pending_contact_info()
IS 'Clear session-pending email and phone.';

-- Grant EXECUTE on the API functions only
GRANT EXECUTE ON FUNCTION set_user_contact_info(text, text)           TO PUBLIC;
GRANT EXECUTE ON FUNCTION get_user_contact(text)                     TO PUBLIC;
GRANT EXECUTE ON FUNCTION update_user_contact(text, text, text) TO postgres;
GRANT EXECUTE ON FUNCTION list_all_user_contacts()                   TO postgres;
GRANT EXECUTE ON FUNCTION clear_pending_contact_info()               TO PUBLIC;
