# PostgreSQL User Contact Extension

A PostgreSQL extension that enforces contact information (email and phone) collection during user creation and provides secure management of user contact details with row-level security.

## Features

- 🔒 **Mandatory Contact Info**: Requires email and phone before creating new database users
- 👤 **Self-Service Updates**: Users can update their own contact information
- 🛡️ **Row-Level Security**: Users can only view their own contact info
- 👑 **Superuser Controls**: Full administrative access for superusers
- 🔄 **UPSERT Support**: Automatically insert or update contact records
- ✏️ **Partial Updates**: Update email or phone independently
- 📊 **Audit Trail**: Automatic tracking of creation and update timestamps

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Creating Users](#creating-users-superuser)
  - [User Self-Service](#user-self-service)
  - [Superuser Administration](#superuser-administration)
- [API Reference](#api-reference)
- [Security Model](#security-model)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)


## Installation

### Prerequisites

- PostgreSQL 12 or higher
- PostgreSQL development headers (`postgresql-server-dev` package)
- C compiler (gcc or clang)

### Build and Install

```bash
# Clone or download the extension files
cd user_contact_extension

# Build the extension
make

# Install (requires superuser privileges)
sudo make install

# Load the extension in your database
psql -U postgres -d your_database -c "CREATE EXTENSION user_contact;"
```

### Files Required

```
user_contact/
├── user_contact.c          # Main C source code
├── user_contact.control    # Extension control file
├── user_contact--1.0.sql   # SQL schema definition
├── Makefile                # Build configuration
└── README.md               # This file
```

### Makefile

```makefile
EXTENSION = user_contact
DATA = user_contact--1.0.sql
MODULES = user_contact

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
```

### Control File (user_contact.control)

```
# user_contact extension
comment = 'User contact information management with mandatory collection'
default_version = '1.0'
module_pathname = '$libdir/user_contact'
relocatable = true
```

## Quick Start

### For Superusers (Creating Users)

```sql
-- 1. Set contact information
SELECT set_user_contact_info('alice@example.com', '1234567890');

-- 2. Create the user
CREATE USER alice WITH PASSWORD 'secure_password';

-- 3. Contact info is automatically stored!
```

### For Normal Users (Self-Service)

```sql
-- View your own contact info
SELECT * FROM my_contact_info;

-- Update your email
SELECT update_my_contact_info('newemail@example.com', NULL);

-- Update your phone
SELECT update_my_contact_info(NULL, '5559876543');
```

## Usage

### Creating Users (Superuser)

#### Method 1: Via CREATE USER Hook (Recommended)

```sql
-- Step 1: Set contact info for the upcoming user
SELECT set_user_contact_info('john@company.com', '5551234567');

-- Step 2: Create the user (contact info is automatically stored)
CREATE USER john WITH PASSWORD 'password123' LOGIN;

-- The extension intercepts CREATE USER and stores the contact info
```

#### Method 2: Direct Insert (Superuser Only)

```sql
-- Create the role first
CREATE USER jane WITH PASSWORD 'password456';

-- Then add contact info directly
SELECT insert_user_contact('jane', 'jane@company.com', '5559876543');
```

#### Method 3: Update with UPSERT

```sql
-- This works even if the user has no contact info yet
SELECT update_user_contact('existing_user', 'email@example.com', '5551112222');
```

### User Self-Service

Normal users can manage their own contact information:

```sql
-- View your contact info (easy way)
SELECT * FROM my_contact_info;

-- View your contact info (function way)
SELECT * FROM get_user_contact(current_user) AS (
    email text, 
    phone text, 
    created_at timestamptz, 
    updated_at timestamptz
);

-- Update both email and phone
SELECT update_my_contact_info('newemail@company.com', '5553334444');

-- Update only email
SELECT update_my_contact_info('newemail@company.com', NULL);

-- Update only phone
SELECT update_my_contact_info(NULL, '5553334444');
```

### Superuser Administration

#### View All Contacts

```sql
-- List all user contacts
SELECT * FROM list_all_user_contacts();

-- Query the table directly
SELECT username, email, phone, created_at, updated_at 
FROM user_contact_info 
ORDER BY created_at DESC;
```

#### Update Any User's Contact Info

```sql
-- Update both fields
SELECT update_user_contact('john', 'john.new@company.com', '5556667777');

-- Update only email
SELECT update_user_contact('john', 'john.new@company.com', NULL);

-- Update only phone
SELECT update_user_contact('john', NULL, '5556667777');

-- UPSERT: Insert if doesn't exist, update if exists
SELECT update_user_contact('new_user', 'new@company.com', '5558889999');
```

#### Direct Table Operations

```sql
-- Superusers can directly query the table
SELECT * FROM user_contact_info WHERE email LIKE '%@company.com';

-- Superusers can directly insert
INSERT INTO user_contact_info (username, email, phone) 
VALUES ('manual_user', 'manual@company.com', '5551112222');

-- Superusers can directly update
UPDATE user_contact_info 
SET phone = '5559998888' 
WHERE username = 'john';

-- Superusers can directly delete
DELETE FROM user_contact_info WHERE username = 'old_user';
```

## API Reference

### Functions

#### `set_user_contact_info(email text, phone text)`
**Access**: PUBLIC  
**Returns**: text  
**Description**: Stores email and phone in session memory for the next CREATE USER command.

```sql
SELECT set_user_contact_info('user@example.com', '1234567890');
```

**Validations**:
- Email must contain '@'
- Phone must be at least 7 characters

---

#### `update_my_contact_info(email text, phone text)`
**Access**: PUBLIC  
**Returns**: void  
**Description**: Allows users to update their own contact information. Either parameter can be NULL.

```sql
-- Update both
SELECT update_my_contact_info('new@example.com', '5551234567');

-- Update only email
SELECT update_my_contact_info('new@example.com', NULL);

-- Update only phone
SELECT update_my_contact_info(NULL, '5551234567');
```

**Permissions**: Any user can update their own info  
**Behavior**: UPSERT - inserts if record doesn't exist

---

#### `get_user_contact(username text)`
**Access**: PUBLIC  
**Returns**: record (email text, phone text, created_at timestamptz, updated_at timestamptz)  
**Description**: Retrieves contact information for a user.

```sql
-- Get your own contact info
SELECT * FROM get_user_contact(current_user) AS (
    email text, 
    phone text, 
    created_at timestamptz, 
    updated_at timestamptz
);

-- Superuser can get any user's info
SELECT * FROM get_user_contact('alice') AS (
    email text, 
    phone text, 
    created_at timestamptz, 
    updated_at timestamptz
);
```

**Permissions**: 
- Users can only get their own info
- Superusers can get any user's info

---

#### `update_user_contact(username text, email text, phone text)`
**Access**: Superuser only  
**Returns**: void  
**Description**: Updates or inserts contact info for any user. Parameters can be NULL for partial updates.

```sql
-- Update both
SELECT update_user_contact('alice', 'alice@example.com', '5551234567');

-- Update only email
SELECT update_user_contact('alice', 'alice@example.com', NULL);

-- Update only phone
SELECT update_user_contact('alice', NULL, '5551234567');
```

**Permissions**: Superuser only  
**Behavior**: UPSERT - inserts if record doesn't exist

---

#### `insert_user_contact(username text, email text, phone text)`
**Access**: Superuser only  
**Returns**: void  
**Description**: Directly inserts contact info into the table.

```sql
SELECT insert_user_contact('bob', 'bob@example.com', '5559876543');
```

**Permissions**: Superuser only  
**Behavior**: INSERT only - fails if record exists

---

#### `list_all_user_contacts()`
**Access**: Superuser only  
**Returns**: SETOF user_contact_info  
**Description**: Returns all contact information records.

```sql
SELECT * FROM list_all_user_contacts();
```

**Permissions**: Superuser only

---

#### `clear_pending_contact_info()`
**Access**: PUBLIC  
**Returns**: text  
**Description**: Clears pending contact info from session memory.

```sql
SELECT clear_pending_contact_info();
```

### Table Schema

#### `user_contact_info`

```sql
CREATE TABLE user_contact_info (
    username    VARCHAR(63)   PRIMARY KEY,
    email       VARCHAR(255)  NOT NULL DEFAULT '',
    phone       VARCHAR(20)   NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CHECK (email = '' OR email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CHECK (phone = '' OR length(phone) >= 7),
    CHECK (email <> '' OR phone <> '')
);
```

**Access**:
- Direct table access controlled by Row-Level Security (RLS)
- Users can SELECT/UPDATE/INSERT their own records
- Superusers have full access

### Views

#### `my_contact_info`

```sql
CREATE VIEW my_contact_info AS
SELECT email, phone, created_at, updated_at
FROM user_contact_info
WHERE username = current_user;
```

**Description**: Convenient view for users to see their own contact information.

```sql
SELECT * FROM my_contact_info;
```

## Security Model

### Row-Level Security (RLS) Policies

The extension implements four RLS policies:

1. **`user_own_contact_select`**: Users can SELECT their own records
2. **`user_own_contact_update`**: Users can UPDATE their own records
3. **`user_own_contact_insert`**: Users can INSERT their own records
4. **`superuser_all_access`**: Superusers bypass all restrictions

### Permission Matrix

| Action | Normal User (Own Data) | Normal User (Other Data) | Superuser |
|--------|------------------------|--------------------------|-----------|
| SELECT own via view | ✅ | ❌ | ✅ |
| SELECT own via table | ✅ | ❌ | ✅ |
| SELECT other via table | ❌ | ❌ | ✅ |
| UPDATE own via function | ✅ | ❌ | ✅ |
| UPDATE own via table | ✅ | ❌ | ✅ |
| UPDATE other via function | ❌ | ❌ | ✅ |
| INSERT own via table | ✅ | ❌ | ✅ |
| INSERT via function | ❌ | ❌ | ✅ |
| DELETE | ❌ | ❌ | ✅ |
| List all contacts | ❌ | ❌ | ✅ |

### Data Validation

All contact information is validated:

- **Email**: Must contain '@' and match email regex pattern
- **Phone**: Must be at least 7 characters long
- **Both**: At least one of email or phone must be provided

## Examples

### Example 1: Onboarding New Users

```sql
-- HR creates multiple users with contact info
SELECT set_user_contact_info('alice@company.com', '555-1001');
CREATE USER alice WITH PASSWORD 'temp123' LOGIN;

SELECT set_user_contact_info('bob@company.com', '555-1002');
CREATE USER bob WITH PASSWORD 'temp456' LOGIN;

SELECT set_user_contact_info('charlie@company.com', '555-1003');
CREATE USER charlie WITH PASSWORD 'temp789' LOGIN;

-- Verify all were created
SELECT username, email, phone FROM user_contact_info 
WHERE username IN ('alice', 'bob', 'charlie');
```

### Example 2: User Updates Their Info

```sql
-- User 'alice' logs in and updates her contact info
SET ROLE alice;

-- Check current info
SELECT * FROM my_contact_info;

-- Update phone number
SELECT update_my_contact_info(NULL, '555-2001');

-- Verify update
SELECT * FROM my_contact_info;

RESET ROLE;
```

### Example 3: Bulk Contact Import

```sql
-- Superuser imports contact info for existing users
SELECT insert_user_contact('user1', 'user1@company.com', '555-3001');
SELECT insert_user_contact('user2', 'user2@company.com', '555-3002');
SELECT insert_user_contact('user3', 'user3@company.com', '555-3003');

-- Or use update_user_contact for UPSERT behavior
SELECT update_user_contact('user4', 'user4@company.com', '555-3004');
```

### Example 4: Contact Info Audit

```sql
-- List users who haven't updated their info in 6 months
SELECT username, email, phone, updated_at
FROM user_contact_info
WHERE updated_at < NOW() - INTERVAL '6 months'
ORDER BY updated_at;

-- Find users with specific email domain
SELECT username, email, phone
FROM user_contact_info
WHERE email LIKE '%@company.com'
ORDER BY username;

-- Check for missing phone numbers
SELECT username, email
FROM user_contact_info
WHERE phone = '' OR phone IS NULL;
```

### Example 5: Error Handling

```sql
-- Attempt to create user without setting contact info
CREATE USER erroruser WITH PASSWORD 'test123';
-- ERROR: Contact information must be set before creating user
-- HINT: Use: SELECT set_user_contact_info('email@example.com', '1234567890'); before CREATE USER

-- Fix: Set contact info first
SELECT set_user_contact_info('erroruser@company.com', '555-9999');
CREATE USER erroruser WITH PASSWORD 'test123';  -- Success!

-- Attempt invalid email
SELECT set_user_contact_info('notanemail', '555-1234');
-- ERROR: Invalid email format

-- Attempt short phone
SELECT set_user_contact_info('valid@email.com', '123');
-- ERROR: Phone number too short
```

### Example 6: Privacy Check

```sql
-- User 'alice' tries to view 'bob's info
SET ROLE alice;

-- This returns no rows (RLS blocks it)
SELECT * FROM user_contact_info WHERE username = 'bob';

-- This raises permission error
SELECT * FROM get_user_contact('bob') AS (
    email text, 
    phone text, 
    created_at timestamptz, 
    updated_at timestamptz
);
-- ERROR: permission denied for user contact info

-- Alice can only see her own info
SELECT * FROM my_contact_info;  -- Works!

RESET ROLE;
```

## Troubleshooting

### Extension Not Loading

**Problem**: Extension fails to load or CREATE EXTENSION fails

**Solution**:
```sql
-- Check if extension is available
SELECT * FROM pg_available_extensions WHERE name = 'user_contact';

-- Check shared_preload_libraries
SHOW shared_preload_libraries;

-- Add to postgresql.conf if using hooks
shared_preload_libraries = 'user_contact'

-- Restart PostgreSQL
sudo systemctl restart postgresql
```

### Contact Info Not Stored After CREATE USER

**Problem**: User is created but contact info is not in the table

**Solution**:
```sql
-- Check if you called set_user_contact_info first
SELECT clear_pending_contact_info();
SELECT set_user_contact_info('email@example.com', '1234567890');
CREATE USER testuser WITH PASSWORD 'password';

-- Check PostgreSQL logs for errors
-- Look for messages starting with "user_contact:"
```

### Permission Denied Errors

**Problem**: Normal user gets "permission denied" when accessing contact info

**Solution**:
```sql
-- For own info, use the view
SELECT * FROM my_contact_info;

-- Or use the function
SELECT * FROM get_user_contact(current_user) AS (
    email text, phone text, created_at timestamptz, updated_at timestamptz
);

-- Users cannot access other users' info by design
```

### Cannot Update Contact Info

**Problem**: User cannot update their contact information

**Solution**:
```sql
-- Use the correct function for self-service
SELECT update_my_contact_info('newemail@example.com', '5551234567');

-- Not this (superuser only):
SELECT update_user_contact(current_user, 'newemail@example.com', '5551234567');
```

### RLS Policies Not Working

**Problem**: Users can see all contact info

**Solution**:
```sql
-- Verify RLS is enabled
SELECT tablename, rowsecurity 
FROM pg_tables 
WHERE tablename = 'user_contact_info';

-- Check policies exist
SELECT * FROM pg_policies WHERE tablename = 'user_contact_info';

-- If needed, re-enable RLS
ALTER TABLE user_contact_info ENABLE ROW LEVEL SECURITY;
```

### Debugging Mode

Enable detailed logging:

```sql
-- Set log level to see extension messages
SET log_min_messages = 'log';

-- Check logs
SELECT set_user_contact_info('test@example.com', '1234567890');
-- Check PostgreSQL log file for "user_contact:" messages
```

## Uninstallation

```sql
-- Drop the extension (as superuser)
DROP EXTENSION user_contact CASCADE;

-- This will:
-- - Remove all functions
-- - Drop the user_contact_info table
-- - Remove the hook
-- - Clean up all related objects
```


