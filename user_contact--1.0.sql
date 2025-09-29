-- user_contact--1.0.sql - CORRECTED VERSION
-- PostgreSQL extension that blocks CREATE USER and provides create_user_with_contact() instead

-- Create the main table
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

-- Enable Row-Level Security
ALTER TABLE user_contact_info ENABLE ROW LEVEL SECURITY;

-- Create RLS policies that allow users to see their own data
-- Policy for users to view their own contact info
CREATE POLICY user_own_contact_select
  ON user_contact_info
  FOR SELECT
  USING (username = current_user);

-- Policy for superusers to see all data
CREATE POLICY superuser_all_access
  ON user_contact_info
  FOR ALL
  USING (pg_has_role(current_user, 'pg_superuser', 'member'))
  WITH CHECK (pg_has_role(current_user, 'pg_superuser', 'member'));

-- Policy to deny all other direct access
CREATE POLICY deny_all_others
  ON user_contact_info
  FOR ALL
  USING (false)
  WITH CHECK (false);

-- =====================================================
-- C FUNCTIONS: Functions that replace CREATE USER
-- =====================================================

-- Main function to create user with contact info (basic version)
CREATE FUNCTION create_user_with_contact(
    username text,
    password text,
    email text,
    phone text
)
RETURNS text
AS 'MODULE_PATHNAME', 'create_user_with_contact'
LANGUAGE C STRICT VOLATILE SECURITY DEFINER;

COMMENT ON FUNCTION create_user_with_contact(text, text, text, text)
IS 'Create a new user with contact information. Replaces CREATE USER. Superuser only.';

-- Extended function to create user with additional PostgreSQL options
CREATE FUNCTION create_user_with_contact(
    username text,
    password text,
    email text,
    phone text,
    additional_options text
)
RETURNS text
AS 'MODULE_PATHNAME', 'create_user_with_contact_extended'
LANGUAGE C STRICT VOLATILE SECURITY DEFINER;

COMMENT ON FUNCTION create_user_with_contact(text, text, text, text, text)
IS 'Create a new user with contact information and additional PostgreSQL user options. Superuser only.';

-- Set contact info directly for an existing user
CREATE FUNCTION set_user_contact_info_direct(username text, email text, phone text)
RETURNS text
AS 'MODULE_PATHNAME', 'set_user_contact_info_direct'
LANGUAGE C STRICT VOLATILE SECURITY DEFINER;

COMMENT ON FUNCTION set_user_contact_info_direct(text, text, text)
IS 'Set contact info directly for an existing user. Creates or updates the record.';

-- Get user contact info (users can see their own data)
-- Return signature changed to TABLE for clarity and to match C return
CREATE FUNCTION get_user_contact(username text)
RETURNS TABLE(
    username text,
    email text,
    phone text,
    created_at timestamptz,
    updated_at timestamptz
)
AS 'MODULE_PATHNAME', 'get_user_contact'
LANGUAGE C STRICT STABLE SECURITY DEFINER;

COMMENT ON FUNCTION get_user_contact(text)
IS 'Return username, email, phone, created_at, updated_at for the given user. Users can only see their own data.';

-- Update contact info with UPSERT and partial updates
CREATE FUNCTION update_user_contact(username text, email text DEFAULT NULL, phone text DEFAULT NULL)
RETURNS void
AS 'MODULE_PATHNAME', 'update_user_contact'
LANGUAGE C VOLATILE SECURITY DEFINER;

COMMENT ON FUNCTION update_user_contact(text, text, text)
IS 'Update a user''s contact info. Users can update their own info. Creates record if it doesn''t exist and both email and phone are provided.';

-- List all user contacts (superuser only)
CREATE FUNCTION list_all_user_contacts()
RETURNS SETOF user_contact_info
AS 'MODULE_PATHNAME', 'list_all_user_contacts'
LANGUAGE C STRICT STABLE SECURITY DEFINER;

COMMENT ON FUNCTION list_all_user_contacts()
IS 'Return all rows from user_contact_info. Superuser only.';

-- Backward compatibility alias
CREATE FUNCTION set_user_contact_info(username text, email text, phone text)
RETURNS text
AS 'MODULE_PATHNAME', 'set_user_contact_info'
LANGUAGE C STRICT VOLATILE SECURITY DEFINER;

COMMENT ON FUNCTION set_user_contact_info(text, text, text)
IS 'Alias for set_user_contact_info_direct for backward compatibility.';

-- =====================================================
-- SQL HELPER FUNCTIONS: Simplified user creation
-- =====================================================

-- Simplified function for creating basic users
CREATE FUNCTION create_basic_user(username text, password text, email text, phone text)
RETURNS text
LANGUAGE SQL
SECURITY DEFINER
AS $$
    SELECT create_user_with_contact(username, password, email, phone);
$$;

COMMENT ON FUNCTION create_basic_user(text, text, text, text)
IS 'Create a basic user with login capability and contact info. Superuser only.';

-- Function for creating users with CREATEDB privilege
CREATE FUNCTION create_user_with_database(
    username text,
    password text,
    email text,
    phone text
)
RETURNS text
LANGUAGE SQL
SECURITY DEFINER
AS $$
    SELECT create_user_with_contact(
        username,
        password,
        email,
        phone,
        'CREATEDB'
    );
$$;

COMMENT ON FUNCTION create_user_with_database(text, text, text, text)
IS 'Create a user with CREATEDB privilege and contact info. Superuser only.';

-- Function for creating admin users
CREATE FUNCTION create_admin_user(
    username text,
    password text,
    email text,
    phone text
)
RETURNS text
LANGUAGE SQL
SECURITY DEFINER
AS $$
    SELECT create_user_with_contact(
        username,
        password,
        email,
        phone,
        'CREATEDB CREATEROLE'
    );
$$;

COMMENT ON FUNCTION create_admin_user(text, text, text, text)
IS 'Create an admin user with CREATEDB and CREATEROLE privileges. Superuser only.';

-- =====================================================
-- Views and helper functions for users
-- =====================================================

-- Create a view that users can query to see their own contact info easily
CREATE VIEW my_contact_info AS
SELECT email, phone, created_at, updated_at
FROM user_contact_info
WHERE username = current_user;

COMMENT ON VIEW my_contact_info
IS 'View for users to easily see their own contact information without specifying username.';

-- Grant SELECT on the view to PUBLIC
GRANT SELECT ON my_contact_info TO PUBLIC;

-- Helper functions for users to manage their own contact info
CREATE FUNCTION update_my_email(new_email text)
RETURNS void
LANGUAGE SQL
SECURITY DEFINER
AS $$
    SELECT update_user_contact(current_user, new_email, NULL);
$$;

CREATE FUNCTION update_my_phone(new_phone text)
RETURNS void
LANGUAGE SQL
SECURITY DEFINER
AS $$
    SELECT update_user_contact(current_user, NULL, new_phone);
$$;

CREATE FUNCTION update_my_contact(new_email text, new_phone text)
RETURNS void
LANGUAGE SQL
SECURITY DEFINER
AS $$
    SELECT update_user_contact(current_user, new_email, new_phone);
$$;

CREATE FUNCTION set_my_contact_info(new_email text, new_phone text)
RETURNS text
LANGUAGE SQL
SECURITY DEFINER
AS $$
    SELECT set_user_contact_info_direct(current_user, new_email, new_phone);
$$;

CREATE FUNCTION get_my_contact_info()
RETURNS TABLE(email text, phone text, created_at timestamptz, updated_at timestamptz)
LANGUAGE SQL
SECURITY DEFINER
AS $$
    -- Use the TABLE-style function get_user_contact and project the desired columns
    SELECT email, phone, created_at, updated_at FROM get_user_contact(current_user);
$$;

-- Grant EXECUTE on helper functions to PUBLIC
GRANT EXECUTE ON FUNCTION update_my_email(text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION update_my_phone(text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION update_my_contact(text, text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION set_my_contact_info(text, text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION get_my_contact_info() TO PUBLIC;

-- =====================================================
-- Validation and utility functions
-- =====================================================

-- Function to validate email format
CREATE FUNCTION validate_email(email_address text)
RETURNS boolean
LANGUAGE SQL
IMMUTABLE
AS $$
    SELECT email_address ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$';
$$;

-- Function to validate phone format
CREATE FUNCTION validate_phone(phone_number text)
RETURNS boolean
LANGUAGE SQL
IMMUTABLE
AS $$
    SELECT length(phone_number) >= 7 AND phone_number ~ '^[0-9+\-\s()\.]+$';
$$;

-- Grant validation functions to PUBLIC
GRANT EXECUTE ON FUNCTION validate_email(text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION validate_phone(text) TO PUBLIC;

-- =====================================================
-- Administrative functions
-- =====================================================

-- Statistics function for admins
CREATE FUNCTION user_contact_stats()
RETURNS TABLE(
    total_users bigint,
    users_with_contact bigint,
    users_without_contact bigint,
    latest_contact_update timestamptz
)
LANGUAGE SQL
SECURITY DEFINER
AS $$
    SELECT
        (SELECT count(*) FROM pg_authid WHERE rolcanlogin = true) as total_users,
        (SELECT count(*) FROM user_contact_info) as users_with_contact,
        (SELECT count(*) FROM pg_authid WHERE rolcanlogin = true) -
        (SELECT count(*) FROM user_contact_info) as users_without_contact,
        (SELECT max(updated_at) FROM user_contact_info) as latest_contact_update;
$$;

-- Search users by email domain (superuser only)
CREATE FUNCTION find_users_by_email_domain(domain_pattern text)
RETURNS SETOF user_contact_info
LANGUAGE SQL
SECURITY DEFINER
AS $$
    SELECT * FROM user_contact_info
    WHERE email ILIKE '%' || domain_pattern || '%'
    ORDER BY username;
$$;

-- =====================================================
-- Views and indexes for performance
-- =====================================================

-- Statistics view (superuser only)
CREATE VIEW contact_info_stats AS
SELECT
    count(*) as total_contacts,
    count(DISTINCT substring(email from '@(.*)')) as unique_domains,
    min(created_at) as earliest_contact,
    max(updated_at) as latest_update,
    avg(length(email)) as avg_email_length,
    avg(length(phone)) as avg_phone_length
FROM user_contact_info;

COMMENT ON VIEW contact_info_stats
IS 'Statistics view for contact information. Superuser access only.';

-- Add useful indexes
CREATE INDEX IF NOT EXISTS idx_user_contact_email ON user_contact_info(email);
CREATE INDEX IF NOT EXISTS idx_user_contact_created_at ON user_contact_info(created_at);
CREATE INDEX IF NOT EXISTS idx_user_contact_updated_at ON user_contact_info(updated_at);
CREATE INDEX IF NOT EXISTS idx_user_contact_email_domain ON user_contact_info((substring(email from '@(.*)')));

-- =====================================================
-- Triggers for automatic timestamp updates
-- =====================================================

-- Trigger function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_contact_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

-- Create trigger on user_contact_info table
CREATE TRIGGER tr_user_contact_updated_at
    BEFORE UPDATE ON user_contact_info
    FOR EACH ROW
    EXECUTE FUNCTION update_contact_updated_at();

-- =====================================================
-- Notification system (optional)
-- =====================================================

-- Notification function for contact updates
CREATE OR REPLACE FUNCTION notify_contact_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM pg_notify('user_contact_change',
            json_build_object(
                'action', 'INSERT',
                'username', NEW.username,
                'email', NEW.email,
                'timestamp', NEW.created_at
            )::text
        );
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        PERFORM pg_notify('user_contact_change',
            json_build_object(
                'action', 'UPDATE',
                'username', NEW.username,
                'old_email', OLD.email,
                'new_email', NEW.email,
                'old_phone', OLD.phone,
                'new_phone', NEW.phone,
                'timestamp', NEW.updated_at
            )::text
        );
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        PERFORM pg_notify('user_contact_change',
            json_build_object(
                'action', 'DELETE',
                'username', OLD.username,
                'timestamp', NOW()
            )::text
        );
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$;

-- Create trigger for notifications
CREATE TRIGGER tr_notify_contact_change
    AFTER INSERT OR UPDATE OR DELETE ON user_contact_info
    FOR EACH ROW
    EXECUTE FUNCTION notify_contact_change();

-- Function to enable/disable contact notifications
CREATE FUNCTION set_contact_notifications(enabled boolean)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    IF enabled THEN 
        EXECUTE 'ALTER TABLE user_contact_info ENABLE TRIGGER tr_notify_contact_change';
    ELSE 
        EXECUTE 'ALTER TABLE user_contact_info DISABLE TRIGGER tr_notify_contact_change';
    END IF;
END;
$$;

COMMENT ON FUNCTION set_contact_notifications(boolean)
IS 'Enable or disable contact change notifications. Superuser only.';

-- =====================================================
-- Grant appropriate permissions
-- =====================================================

-- Grant EXECUTE on user creation functions to postgres (superuser role)
GRANT EXECUTE ON FUNCTION create_user_with_contact(text, text, text, text) TO postgres;
GRANT EXECUTE ON FUNCTION create_user_with_contact(text, text, text, text, text) TO postgres;
GRANT EXECUTE ON FUNCTION create_basic_user(text, text, text, text) TO postgres;
GRANT EXECUTE ON FUNCTION create_user_with_database(text, text, text, text) TO postgres;
GRANT EXECUTE ON FUNCTION create_admin_user(text, text, text, text) TO postgres;

-- Grant EXECUTE on contact management functions to PUBLIC
GRANT EXECUTE ON FUNCTION set_user_contact_info_direct(text, text, text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION set_user_contact_info(text, text, text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION get_user_contact(text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION update_user_contact(text, text, text) TO PUBLIC;

-- Grant superuser-only functions to postgres
GRANT EXECUTE ON FUNCTION list_all_user_contacts() TO postgres;
GRANT EXECUTE ON FUNCTION user_contact_stats() TO postgres;
GRANT EXECUTE ON FUNCTION find_users_by_email_domain(text) TO postgres;
GRANT EXECUTE ON FUNCTION set_contact_notifications(boolean) TO postgres;

-- Grant stats view to postgres
GRANT SELECT ON contact_info_stats TO postgres;

-- =====================================================
-- Usage examples and documentation
-- =====================================================

-- Create a function that shows usage examples
CREATE FUNCTION show_user_contact_usage()
RETURNS text
LANGUAGE SQL
AS $$
    SELECT $usage$
USER_CONTACT EXTENSION USAGE EXAMPLES:

1. CREATE A NEW USER (replaces CREATE USER):
   SELECT create_user_with_contact('john_doe', 'secure_password', 'john@example.com', '1234567890');

2. CREATE A USER WITH ADDITIONAL OPTIONS:
   SELECT create_user_with_contact('admin_user', 'admin_pass', 'admin@example.com', '9876543210', 'CREATEDB CREATEROLE');

3. CREATE BASIC USER (helper function):
   SELECT create_basic_user('simple_user', 'password', 'user@example.com', '5555555555');

4. VIEW YOUR OWN CONTACT INFO:
   SELECT * FROM my_contact_info;

5. UPDATE YOUR OWN CONTACT INFO:
   SELECT update_my_email('newemail@example.com');
   SELECT update_my_phone('9999999999');
   SELECT update_my_contact('new@example.com', '8888888888');

6. SET CONTACT INFO FOR EXISTING USER (superuser or self):
   SELECT set_user_contact_info_direct('existing_user', 'email@example.com', '7777777777');

7. VALIDATE EMAIL/PHONE:
   SELECT validate_email('test@example.com');
   SELECT validate_phone('1234567890');

8. ADMIN FUNCTIONS (superuser only):
   SELECT * FROM list_all_user_contacts();
   SELECT * FROM user_contact_stats();
   SELECT * FROM find_users_by_email_domain('example.com');

NOTE: Direct CREATE USER statements are blocked. Use create_user_with_contact() instead.
$usage$;
$$;

GRANT EXECUTE ON FUNCTION show_user_contact_usage() TO PUBLIC;

COMMENT ON FUNCTION show_user_contact_usage()
IS 'Display usage examples and help for the user_contact extension.';
