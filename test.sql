-- =============================================================================
-- Setup (as superuser)
-- =============================================================================

-- Load the extension
CREATE EXTENSION user_contact;

-- =============================================================================
-- Test 1: Normal user creation with contact info
-- =============================================================================

-- Set contact info
SELECT set_user_contact_info('alice@example.com', '1234567890');

-- Create user
CREATE USER alice WITH PASSWORD 'password123';

-- Verify contact was stored
SELECT * FROM get_user_contact('alice') AS (email text, phone text, created_at timestamptz, updated_at timestamptz);

-- =============================================================================
-- Test 2: Superuser direct INSERT
-- =============================================================================

-- Superuser can directly insert contact info without CREATE USER hook
SELECT insert_user_contact('bob', 'bob@example.com', '9876543210');

-- Verify
SELECT * FROM user_contact_info WHERE username = 'bob';

-- =============================================================================
-- Test 3: Dynamic username (current_user, not hardcoded 'postgres')
-- =============================================================================

-- Check who has execute permission on superuser functions
SELECT 
    p.proname,
    pg_catalog.pg_get_userbyid(a.grantee) as grantee,
    a.privilege_type
FROM pg_proc p
JOIN information_schema.routine_privileges a 
    ON p.proname = a.routine_name
WHERE p.proname IN ('update_user_contact', 'insert_user_contact', 'list_all_user_contacts')
ORDER BY p.proname, grantee;

-- =============================================================================
-- Test 4: Row-Level Security - Non-superuser SELECT
-- =============================================================================

-- Create a test user with contact info
SELECT set_user_contact_info('charlie@example.com', '5551234567');
CREATE USER charlie WITH PASSWORD 'password123';

-- Grant charlie permission to connect
GRANT CONNECT ON DATABASE postgres TO charlie;

-- Switch to charlie (in a new session or use SET ROLE)
SET ROLE charlie;

-- Charlie can see his own info
SELECT * FROM my_contact_info;

-- Charlie CAN'T see other users' info (should return no rows)
SELECT * FROM user_contact_info WHERE username = 'alice';

-- This will work (via function with permission check)
SELECT * FROM get_user_contact('charlie') AS (email text, phone text, created_at timestamptz, updated_at timestamptz);

-- This should fail with permission error
SELECT * FROM get_user_contact('alice') AS (email text, phone text, created_at timestamptz, updated_at timestamptz);

-- Switch back to superuser
RESET ROLE;

-- =============================================================================
-- Test 5: Normal user updating their own contact info
-- =============================================================================

SET ROLE charlie;

-- Charlie updates his own email
SELECT update_my_contact_info('charlie.new@example.com', NULL);

-- Charlie updates his own phone
SELECT update_my_contact_info(NULL, '5559876543');

-- Charlie updates both
SELECT update_my_contact_info('charlie.updated@example.com', '5551111111');

-- Verify the update
SELECT * FROM my_contact_info;

RESET ROLE;

-- =============================================================================
-- Test 6: UPSERT - Update creates record if not exists
-- =============================================================================

-- Try to update a user that doesn't exist in the table yet
-- First create the role
CREATE USER david WITH PASSWORD 'password123';

-- Update (which will INSERT since david is not in user_contact_info)
SELECT update_user_contact('david', 'david@example.com', '5552223333');

-- Verify it was inserted
SELECT * FROM user_contact_info WHERE username = 'david';

-- Now actually update it
SELECT update_user_contact('david', 'david.new@example.com', NULL);

-- Verify the update (phone should remain the same)
SELECT * FROM user_contact_info WHERE username = 'david';

-- =============================================================================
-- Test 7: Partial updates (either email or phone)
-- =============================================================================

-- Update only email for alice
SELECT update_user_contact('alice', 'alice.updated@example.com', NULL);

-- Verify
SELECT username, email, phone FROM user_contact_info WHERE username = 'alice';

-- Update only phone for alice
SELECT update_user_contact('alice', NULL, '5554445555');

-- Verify
SELECT username, email, phone FROM user_contact_info WHERE username = 'alice';

-- =============================================================================
-- Test 8: List all contacts (superuser only)
-- =============================================================================

-- As superuser, list all contacts
SELECT * FROM list_all_user_contacts();

-- As normal user, this should fail
SET ROLE charlie;
SELECT * FROM list_all_user_contacts();  -- Should error: must be superuser

RESET ROLE;

-- =============================================================================
-- Test 9: Error handling
-- =============================================================================

-- Try to create user without setting contact info first
CREATE USER erroruser WITH PASSWORD 'password123';
-- Should fail: Contact information must be set before creating user

-- Try invalid email
SELECT set_user_contact_info('notanemail', '1234567890');
-- Should fail: Invalid email format

-- Try short phone
SELECT set_user_contact_info('test@example.com', '123');
-- Should fail: Phone number too short

-- Try to update without providing either field
SELECT update_user_contact('alice', NULL, NULL);
-- Should fail: At least one of email or phone must be provided

-- =============================================================================
-- Test 10: Verify RLS policies are working
-- =============================================================================

-- Check active policies
SELECT 
    schemaname, 
    tablename, 
    policyname, 
    permissive, 
    roles,
    cmd,
    qual,
    with_check
FROM pg_policies 
WHERE tablename = 'user_contact_info';

-- =============================================================================
-- Cleanup
-- =============================================================================

-- Drop test users
DROP USER IF EXISTS alice;
DROP USER IF EXISTS bob;
DROP USER IF EXISTS charlie;
DROP USER IF EXISTS david;
DROP USER IF EXISTS erroruser;

-- Clear the contact info
TRUNCATE user_contact_info;