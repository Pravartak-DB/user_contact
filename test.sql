-- automated_test.sql - Quick validation script for user_contact extension
-- Run with: psql -d test_database -f automated_test.sql

\set ON_ERROR_STOP on
\timing on

-- Test setup
\echo '=== STARTING USER_CONTACT EXTENSION TESTS ==='

-- Test 1: Verify extension exists
\echo '--- Test 1: Extension Status ---'
SELECT 
    CASE 
        WHEN count(*) > 0 THEN 'PASS: Extension loaded'
        ELSE 'FAIL: Extension not found'
    END as result
FROM pg_extension WHERE extname = 'user_contact';

-- Test 2: Verify table exists with RLS
\echo '--- Test 2: Table and RLS Status ---'
SELECT 
    CASE 
        WHEN EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'user_contact_info')
        AND EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'user_contact_info' AND rowsecurity = true)
        THEN 'PASS: Table exists with RLS enabled'
        ELSE 'FAIL: Table missing or RLS disabled'
    END as result;

-- Test 3: CREATE USER should be blocked
\echo '--- Test 3: CREATE USER Blocking ---'
DO $$
DECLARE
    blocked boolean := false;
BEGIN
    BEGIN
        CREATE USER test_blocked_user WITH PASSWORD 'should_fail';
    EXCEPTION
        WHEN feature_not_supported THEN
            blocked := true;
    END;
    
    IF blocked THEN
        RAISE NOTICE 'PASS: CREATE USER properly blocked';
    ELSE
        RAISE NOTICE 'FAIL: CREATE USER was not blocked';
        -- Cleanup if it wasn't blocked
        DROP USER IF EXISTS test_blocked_user;
    END IF;
END $$;

-- Test 4: User creation with contact should work
\echo '--- Test 4: User Creation with Contact ---'
DO $$
DECLARE
    result text;
BEGIN
    SELECT create_user_with_contact(
        'auto_test_user',
        'test_password_123',
        'autotest@example.com',
        '5551234567'
    ) INTO result;
    
    IF result IS NOT NULL THEN
        RAISE NOTICE 'PASS: User created with contact info';
    ELSE
        RAISE NOTICE 'FAIL: User creation returned NULL';
    END IF;
EXCEPTION
    WHEN OTHERS THEN
        RAISE NOTICE 'FAIL: User creation failed: %', SQLERRM;
END $$;

-- Test 5: Verify user and contact data
\echo '--- Test 5: Data Verification ---'
SELECT 
    CASE 
        WHEN EXISTS (SELECT 1 FROM pg_authid WHERE rolname = 'auto_test_user' AND rolcanlogin = true)
        AND EXISTS (SELECT 1 FROM user_contact_info WHERE username = 'auto_test_user')
        THEN 'PASS: User and contact data both exist'
        ELSE 'FAIL: Missing user or contact data'
    END as result;

-- Test 6: Contact info update
\echo '--- Test 6: Contact Update ---'
DO $$
BEGIN
    PERFORM update_user_contact('auto_test_user', 'updated@example.com', '5559876543');
    
    IF EXISTS (
        SELECT 1 FROM user_contact_info 
        WHERE username = 'auto_test_user' 
        AND email = 'updated@example.com' 
        AND phone = '5559876543'
    ) THEN
        RAISE NOTICE 'PASS: Contact info updated successfully';
    ELSE
        RAISE NOTICE 'FAIL: Contact info update failed';
    END IF;
END $$;

-- Test 7: Helper functions exist
\echo '--- Test 7: Helper Functions ---'
SELECT 
    CASE 
        WHEN COUNT(*) >= 10 THEN 'PASS: All major functions exist'
        ELSE 'FAIL: Missing functions, found: ' || COUNT(*)::text
    END as result
FROM pg_proc p
JOIN pg_namespace n ON p.pronamespace = n.oid
WHERE n.nspname = 'public'
AND p.proname LIKE '%user_contact%' 
   OR p.proname LIKE 'create_%user%'
   OR p.proname LIKE 'update_my_%'
   OR p.proname LIKE 'validate_%';

-- Test 8: Validation functions
\echo '--- Test 8: Validation Functions ---'
SELECT 
    CASE 
        WHEN validate_email('test@example.com') = true 
        AND validate_email('invalid.email') = false
        AND validate_phone('1234567890') = true
        AND validate_phone('123') = false
        THEN 'PASS: Validation functions work correctly'
        ELSE 'FAIL: Validation functions not working properly'
    END as result;

-- Test 9: Permission enforcement
\echo '--- Test 9: Permission Test (as test user) ---'
\c - auto_test_user

DO $$
DECLARE
    access_denied boolean := false;
BEGIN
    BEGIN
        PERFORM create_user_with_contact('should_fail', 'pass', 'fail@test.com', '1234567890');
    EXCEPTION
        WHEN insufficient_privilege THEN
            access_denied := true;
    END;
    
    IF access_denied THEN
        RAISE NOTICE 'PASS: Non-superuser properly denied user creation';
    ELSE
        RAISE NOTICE 'FAIL: Non-superuser was allowed to create users';
    END IF;
END $$;

-- Test user can see own contact info
SELECT 
    CASE 
        WHEN EXISTS (SELECT 1 FROM my_contact_info)
        THEN 'PASS: User can view own contact info'
        ELSE 'FAIL: User cannot view own contact info'
    END as result;

-- Reconnect as superuser for cleanup
\c - postgres

-- Test 10: Administrative functions (superuser only)
\echo '--- Test 10: Admin Functions ---'
SELECT 
    CASE 
        WHEN count(*) > 0 THEN 'PASS: Can list user contacts'
        ELSE 'FAIL: Cannot list user contacts'
    END as result
FROM list_all_user_contacts();

-- Check statistics function
SELECT 
    CASE 
        WHEN total_users > 0 AND users_with_contact > 0 
        THEN 'PASS: Statistics function works'
        ELSE 'FAIL: Statistics function issues'
    END as result
FROM user_contact_stats();

-- Cleanup
\echo '--- Cleanup ---'
DROP USER IF EXISTS auto_test_user;
DELETE FROM user_contact_info WHERE username = 'auto_test_user';

-- Final status
\echo '=== TESTS COMPLETED ==='
\echo 'Review the PASS/FAIL messages above for detailed results.'
\echo 'All tests should show PASS for a working extension.'

\timing off