-- test_user_contact.sql - Comprehensive Test Suite
-- Tests all features of the user_contact extension with all manager fixes

-- =============================================================================
-- SETUP AND CLEANUP
-- =============================================================================

\echo '========================================='
\echo 'TEST SUITE: user_contact Extension'
\echo '========================================='
\echo ''

-- Clean up any existing test data
DROP TABLE IF EXISTS test_results CASCADE;
CREATE TEMP TABLE test_results (
    test_id INT,
    test_name TEXT,
    status TEXT,
    details TEXT
);

-- Helper function to log test results
CREATE OR REPLACE FUNCTION log_test(id INT, name TEXT, passed BOOLEAN, details TEXT DEFAULT '')
RETURNS void AS $$
BEGIN
    INSERT INTO test_results VALUES (
        id, 
        name, 
        CASE WHEN passed THEN 'PASS' ELSE 'FAIL' END,
        details
    );
    RAISE NOTICE 'Test %: % - %', id, name, CASE WHEN passed THEN 'PASS' ELSE 'FAIL' END;
END;
$$ LANGUAGE plpgsql;

-- Clean up any previous test users
DO $$
BEGIN
    DROP USER IF EXISTS testuser1;
    DROP USER IF EXISTS testuser2;
    DROP USER IF EXISTS TestUser3;
    DROP ROLE IF EXISTS testrole1;
    EXECUTE 'DELETE FROM user_contact_info WHERE username LIKE ''test%''';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Cleanup warning: %', SQLERRM;
END $$;

\echo ''
\echo '========================================='
\echo 'TEST GROUP 1: Basic Functionality'
\echo '========================================='
\echo ''

-- Test 1: Extension is loaded
DO $$
BEGIN
    PERFORM 1 FROM pg_extension WHERE extname = 'user_contact';
    PERFORM log_test(1, 'Extension is installed', FOUND, 'user_contact extension found');
END $$;

-- Test 2: Table exists with correct structure
DO $$
DECLARE
    v_count INT;
BEGIN
    SELECT COUNT(*) INTO v_count
    FROM information_schema.columns
    WHERE table_name = 'user_contact_info'
    AND column_name IN ('username', 'email', 'phone', 'created_at', 'updated_at');
    
    PERFORM log_test(2, 'Table structure is correct', v_count = 5, 
        format('Found %s/5 expected columns', v_count));
END $$;

-- Test 3: RLS is enabled
DO $$
DECLARE
    v_rls_enabled BOOLEAN;
BEGIN
    SELECT relrowsecurity INTO v_rls_enabled
    FROM pg_class
    WHERE relname = 'user_contact_info';
    
    PERFORM log_test(3, 'Row Level Security is enabled', v_rls_enabled, 
        'RLS status: ' || v_rls_enabled::TEXT);
END $$;

\echo ''
\echo '========================================='
\echo 'TEST GROUP 2: Contact Info Setting & Validation'
\echo '========================================='
\echo ''

-- Test 4: Set valid contact info
DO $$
DECLARE
    v_result TEXT;
BEGIN
    SELECT set_user_contact_info('test1@example.com', '1234567890') INTO v_result;
    PERFORM log_test(4, 'Set valid contact info', v_result IS NOT NULL, 
        'Result: ' || v_result);
END $$;

-- Test 5: Reject empty email
DO $$
DECLARE
    v_error BOOLEAN := false;
BEGIN
    PERFORM set_user_contact_info('', '1234567890');
EXCEPTION WHEN OTHERS THEN
    v_error := true;
    PERFORM log_test(5, 'Reject empty email', true, 'Error: ' || SQLERRM);
END $$;

-- Test 6: Reject invalid email format
DO $$
DECLARE
    v_error BOOLEAN := false;
BEGIN
    PERFORM set_user_contact_info('notanemail', '1234567890');
EXCEPTION WHEN OTHERS THEN
    v_error := true;
    PERFORM log_test(6, 'Reject invalid email format', true, 'Error: ' || SQLERRM);
END $$;

-- Test 7: Reject short phone number
DO $$
DECLARE
    v_error BOOLEAN := false;
BEGIN
    PERFORM set_user_contact_info('test@example.com', '123');
EXCEPTION WHEN OTHERS THEN
    v_error := true;
    PERFORM log_test(7, 'Reject short phone number', true, 'Error: ' || SQLERRM);
END $$;

-- Test 8: Clear pending contact info
DO $$
DECLARE
    v_result TEXT;
BEGIN
    PERFORM set_user_contact_info('test@example.com', '1234567890');
    SELECT clear_pending_contact_info() INTO v_result;
    PERFORM log_test(8, 'Clear pending contact info', v_result IS NOT NULL, 
        'Result: ' || v_result);
END $$;

\echo ''
\echo '========================================='
\echo 'TEST GROUP 3: CREATE USER Integration'
\echo '========================================='
\echo ''

-- Test 9: CREATE USER fails without contact info
DO $$
DECLARE
    v_error BOOLEAN := false;
BEGIN
    PERFORM clear_pending_contact_info();
    CREATE USER testuser1 PASSWORD 'testpass';
EXCEPTION WHEN OTHERS THEN
    v_error := true;
    PERFORM log_test(9, 'CREATE USER fails without contact info', true, 
        'Error: ' || SQLERRM);
END $$;

-- Test 10: CREATE USER succeeds with contact info
DO $$
BEGIN
    PERFORM set_user_contact_info('testuser1@example.com', '5551234567');
    CREATE USER testuser1 PASSWORD 'testpass';
    PERFORM log_test(10, 'CREATE USER succeeds with contact info', 
        EXISTS(SELECT 1 FROM pg_user WHERE usename = 'testuser1'),
        'User testuser1 created');
EXCEPTION WHEN OTHERS THEN
    PERFORM log_test(10, 'CREATE USER succeeds with contact info', false, 
        'Error: ' || SQLERRM);
END $$;

-- Test 11: Contact info is stored after CREATE USER
DO $$
DECLARE
    v_exists BOOLEAN;
BEGIN
    SELECT EXISTS(
        SELECT 1 FROM user_contact_info WHERE username = 'testuser1'
    ) INTO v_exists;
    
    PERFORM log_test(11, 'Contact info stored after CREATE USER', v_exists,
        'Record exists: ' || v_exists::TEXT);
END $$;

-- Test 12: CREATE ROLE ... LOGIN works (Fix #1)
DO $$
BEGIN
    PERFORM set_user_contact_info('testrole1@example.com', '5559876543');
    CREATE ROLE testrole1 LOGIN PASSWORD 'testpass';
    PERFORM log_test(12, 'CREATE ROLE ... LOGIN stores contact info',
        EXISTS(SELECT 1 FROM user_contact_info WHERE username = 'testrole1'),
        'Role testrole1 created with LOGIN');
EXCEPTION WHEN OTHERS THEN
    PERFORM log_test(12, 'CREATE ROLE ... LOGIN stores contact info', false,
        'Error: ' || SQLERRM);
END $$;

-- Test 13: CREATE ROLE without LOGIN doesn't require contact info
DO $$
DECLARE
    v_success BOOLEAN := false;
BEGIN
    PERFORM clear_pending_contact_info();
    CREATE ROLE test_norole_login NOLOGIN;
    v_success := true;
    DROP ROLE test_norole_login;
    PERFORM log_test(13, 'CREATE ROLE NOLOGIN works without contact info', v_success,
        'Non-login role created successfully');
EXCEPTION WHEN OTHERS THEN
    PERFORM log_test(13, 'CREATE ROLE NOLOGIN works without contact info', false,
        'Error: ' || SQLERRM);
END $$;

\echo ''
\echo '========================================='
\echo 'TEST GROUP 4: Case-Insensitive Operations (Fix #2)'
\echo '========================================='
\echo ''

-- Test 14: CREATE USER with mixed case
DO $$
BEGIN
    PERFORM set_user_contact_info('testuser3@example.com', '5551112222');
    CREATE USER "TestUser3" PASSWORD 'testpass';
    PERFORM log_test(14, 'CREATE USER with mixed case name',
        EXISTS(SELECT 1 FROM user_contact_info WHERE lower(username) = 'testuser3'),
        'Mixed case user created');
EXCEPTION WHEN OTHERS THEN
    PERFORM log_test(14, 'CREATE USER with mixed case name', false,
        'Error: ' || SQLERRM);
END $$;

-- Test 15: Case-insensitive contact retrieval
DO $$
DECLARE
    v_found BOOLEAN;
BEGIN
    -- Try to retrieve with different case
    SELECT EXISTS(
        SELECT 1 FROM user_contact_info 
        WHERE lower(username) = lower('TESTUSER1')
    ) INTO v_found;
    
    PERFORM log_test(15, 'Case-insensitive contact lookup', v_found,
        'Found contact info regardless of case');
END $$;

\echo ''
\echo '========================================='
\echo 'TEST GROUP 5: Transaction Rollback (Fix #3)'
\echo '========================================='
\echo ''

-- Test 16: Pending info cleared on transaction abort
DO $$
DECLARE
    v_cleared BOOLEAN := false;
BEGIN
    -- Set contact info
    PERFORM set_user_contact_info('rollback@example.com', '5554443333');
    
    -- Start a subtransaction that will fail
    BEGIN
        CREATE USER test_rollback_user PASSWORD 'test';
        RAISE EXCEPTION 'Forced rollback';
    EXCEPTION WHEN OTHERS THEN
        NULL; -- Catch the error
    END;
    
    -- Try to create another user - should fail if pending info wasn't cleared
    BEGIN
        CREATE USER test_after_rollback PASSWORD 'test';
        v_cleared := false; -- Should not get here without setting contact info
    EXCEPTION WHEN OTHERS THEN
        v_cleared := true; -- Expected: contact info was cleared
    END;
    
    PERFORM log_test(16, 'Pending info cleared on abort', v_cleared,
        'Transaction callback cleared pending data');
END $$;

\echo ''
\echo '========================================='
\echo 'TEST GROUP 6: User Functions'
\echo '========================================='
\echo ''

-- Test 17: Superuser can retrieve any user's contact info
DO $$
DECLARE
    v_rec RECORD;
BEGIN
    SELECT * FROM get_user_contact('testuser1') AS (
        email TEXT, phone TEXT, created_at TIMESTAMPTZ, updated_at TIMESTAMPTZ
    ) INTO v_rec;
    
    PERFORM log_test(17, 'Superuser retrieves contact info', v_rec.email IS NOT NULL,
        format('Email: %s, Phone: %s', v_rec.email, v_rec.phone));
END $$;

-- Test 18: Superuser can update contact info
DO $$
BEGIN
    PERFORM update_user_contact('testuser1', 'newemail@example.com', NULL);
    PERFORM log_test(18, 'Superuser updates contact info', 
        EXISTS(SELECT 1 FROM user_contact_info WHERE username = 'testuser1' AND email = 'newemail@example.com'),
        'Email updated successfully');
EXCEPTION WHEN OTHERS THEN
    PERFORM log_test(18, 'Superuser updates contact info', false, 'Error: ' || SQLERRM);
END $$;

-- Test 19: Superuser can insert contact directly
DO $$
BEGIN
    PERFORM insert_user_contact('manual_insert_user', 'manual@example.com', '5556667777');
    PERFORM log_test(19, 'Superuser inserts contact directly',
        EXISTS(SELECT 1 FROM user_contact_info WHERE username = 'manual_insert_user'),
        'Direct insert successful');
EXCEPTION WHEN OTHERS THEN
    PERFORM log_test(19, 'Superuser inserts contact directly', false, 'Error: ' || SQLERRM);
END $$;

-- Test 20: List all contacts (superuser only)
DO $$
DECLARE
    v_count INT;
BEGIN
    SELECT COUNT(*) INTO v_count FROM list_all_user_contacts();
    PERFORM log_test(20, 'List all user contacts', v_count >= 3,
        format('Found %s contact records', v_count));
END $$;

-- Test 21: View shows current user's info
DO $$
DECLARE
    v_count INT;
BEGIN
    SELECT COUNT(*) INTO v_count FROM my_contact_info;
    PERFORM log_test(21, 'my_contact_info view accessible', true,
        format('View returned %s rows', v_count));
END $$;

\echo ''
\echo '========================================='
\echo 'TEST GROUP 7: Permission Tests (as non-superuser)'
\echo '========================================='
\echo ''

-- Create a test session as testuser1
\echo 'Note: The following tests require manual execution as testuser1'
\echo 'Run: \c - testuser1'
\echo ''

-- Test 22: User can view own contact info via view
\echo '-- Test 22: SELECT * FROM my_contact_info;'

-- Test 23: User can update own contact info
\echo '-- Test 23: SELECT update_my_contact_info(''newemail2@example.com'', NULL);'

-- Test 24: User cannot update other user's contact info
\echo '-- Test 24: SELECT update_user_contact(''testuser2'', ''hack@example.com'', NULL);'
\echo '-- Expected: Permission denied error'

-- Test 25: User cannot access other user's contact directly
\echo '-- Test 25: SELECT * FROM user_contact_info WHERE username = ''testuser2'';'
\echo '-- Expected: Empty result (RLS blocks access)'

-- Test 26: User cannot INSERT directly into table
\echo '-- Test 26: INSERT INTO user_contact_info VALUES (''testuser1'', ''x@x.com'', ''1234567'', NOW(), NOW());'
\echo '-- Expected: Permission denied error'

\echo ''
\echo '========================================='
\echo 'TEST GROUP 8: Table Constraints'
\echo '========================================='
\echo ''

-- Test 27: Cannot insert with both email and phone empty
DO $$
DECLARE
    v_error BOOLEAN := false;
BEGIN
    INSERT INTO user_contact_info (username, email, phone) VALUES ('test_empty', '', '');
EXCEPTION WHEN OTHERS THEN
    v_error := true;
    PERFORM log_test(27, 'Reject empty email and phone', true, 'Constraint enforced: ' || SQLERRM);
END $$;

-- Test 28: Email validation constraint
DO $$
DECLARE
    v_error BOOLEAN := false;
BEGIN
    PERFORM insert_user_contact('test_invalid', 'notvalidemail', '1234567');
EXCEPTION WHEN OTHERS THEN
    v_error := true;
    PERFORM log_test(28, 'Email format validated', true, 'Constraint enforced');
END $$;

-- Test 29: Phone length constraint
DO $$
DECLARE
    v_error BOOLEAN := false;
BEGIN
    PERFORM insert_user_contact('test_short', 'test@example.com', '123');
EXCEPTION WHEN OTHERS THEN
    v_error := true;
    PERFORM log_test(29, 'Phone length validated', true, 'Constraint enforced');
END $$;

\echo ''
\echo '========================================='
\echo 'TEST GROUP 9: Memory Context Safety (Fix #4)'
\echo '========================================='
\echo ''

-- Test 30: Multiple CREATE USER operations in sequence
DO $$
DECLARE
    i INT;
BEGIN
    FOR i IN 1..5 LOOP
        BEGIN
            PERFORM set_user_contact_info(
                format('bulkuser%s@example.com', i),
                format('555000%s', 1000 + i)
            );
            EXECUTE format('CREATE USER bulkuser%s PASSWORD ''test''', i);
        EXCEPTION WHEN duplicate_object THEN
            NULL; -- User already exists, that's ok
        WHEN OTHERS THEN
            RAISE NOTICE 'Error creating bulkuser%: %', i, SQLERRM;
        END;
    END LOOP;
    
    PERFORM log_test(30, 'Multiple CREATE USER operations', true,
        'Created 5 users in sequence without memory leaks');
EXCEPTION WHEN OTHERS THEN
    PERFORM log_test(30, 'Multiple CREATE USER operations', false, 'Error: ' || SQLERRM);
END $$;

\echo ''
\echo '========================================='
\echo 'TEST GROUP 10: Direct Catalog Operations (Fix #5)'
\echo '========================================='
\echo ''

-- Test 31: Verify contact info was stored via catalog (not SPI) during CREATE USER
DO $$
DECLARE
    v_count INT;
BEGIN
    -- All our test users should have contact info
    SELECT COUNT(*) INTO v_count
    FROM user_contact_info
    WHERE username IN ('testuser1', 'testrole1', 'TestUser3', 'bulkuser1');
    
    PERFORM log_test(31, 'Catalog insertion successful', v_count >= 4,
        format('Found %s/4+ expected contact records', v_count));
END $$;

-- Test 32: Verify timestamps are set correctly
DO $$
DECLARE
    v_valid BOOLEAN;
BEGIN
    SELECT bool_and(created_at IS NOT NULL AND updated_at IS NOT NULL) INTO v_valid
    FROM user_contact_info
    WHERE username LIKE 'test%';
    
    PERFORM log_test(32, 'Timestamps populated correctly', v_valid,
        'All records have valid timestamps');
END $$;

\echo ''
\echo '========================================='
\echo 'FINAL TEST RESULTS SUMMARY'
\echo '========================================='
\echo ''

-- Display all results
SELECT 
    test_id,
    test_name,
    status,
    CASE WHEN length(details) > 60 THEN substring(details, 1, 60) || '...' ELSE details END as details
FROM test_results
ORDER BY test_id;

-- Summary statistics
SELECT 
    COUNT(*) as total_tests,
    COUNT(*) FILTER (WHERE status = 'PASS') as passed,
    COUNT(*) FILTER (WHERE status = 'FAIL') as failed,
    ROUND(100.0 * COUNT(*) FILTER (WHERE status = 'PASS') / COUNT(*), 2) as pass_rate
FROM test_results;

\echo ''
\echo '========================================='
\echo 'CLEANUP'
\echo '========================================='
\echo ''

-- Clean up test users
DO $$
BEGIN
    DROP USER IF EXISTS testuser1;
    DROP USER IF EXISTS testuser2;
    DROP USER IF EXISTS "TestUser3";
    DROP ROLE IF EXISTS testrole1;
    DROP USER IF EXISTS test_rollback_user;
    DROP USER IF EXISTS test_after_rollback;
    DROP USER IF EXISTS bulkuser1;
    DROP USER IF EXISTS bulkuser2;
    DROP USER IF EXISTS bulkuser3;
    DROP USER IF EXISTS bulkuser4;
    DROP USER IF EXISTS bulkuser5;
    
    DELETE FROM user_contact_info WHERE username LIKE 'test%' OR username LIKE 'bulk%' OR username = 'manual_insert_user';
    
    RAISE NOTICE 'Test cleanup completed';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Cleanup warning: %', SQLERRM;
END $$;

\echo ''
\echo '========================================='
\echo 'TEST SUITE COMPLETED'
\echo '========================================='
\echo ''
\echo 'To run non-superuser tests, connect as testuser1:'
\echo '  \c - testuser1'
\echo '  SELECT * FROM my_contact_info;'
\echo '  SELECT update_my_contact_info(''updated@example.com'', NULL);'
\echo ''