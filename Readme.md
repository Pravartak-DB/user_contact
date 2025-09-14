# PostgreSQL User Contact Extension

A PostgreSQL extension that enforces contact information (email and phone) requirements when creating database users. This extension automatically captures and stores contact information during user creation while maintaining strict security controls.

## Features

- **Mandatory Contact Info**: Requires email and phone number before creating any database user
- **Automatic Storage**: Seamlessly stores contact information during `CREATE USER` commands
- **Security First**: Uses Row-Level Security (RLS) to protect contact data
- **API Functions**: Provides secure C-language functions for contact management
- **Input Validation**: Built-in email and phone number validation
- **Audit Trail**: Tracks creation and update timestamps

## Architecture

The extension consists of:
- A secured `user_contact_info` table with RLS enabled
- A ProcessUtility hook that intercepts `CREATE USER` commands
- C-language API functions for contact management
- Comprehensive logging and error handling

## Installation

### Prerequisites

- PostgreSQL 12+ with development headers
- C compiler (gcc/clang)
- PostgreSQL extension development tools

### Build and Install

```bash
# Compile the extension
gcc -shared -fPIC -I$(pg_config --includedir-server) \
    user_contact.c -o user_contact.so

# Copy files to PostgreSQL directories
sudo cp user_contact.so $(pg_config --pkglibdir)/
sudo cp user_contact--1.0.sql $(pg_config --sharedir)/extension/
sudo cp user_contact.control $(pg_config --sharedir)/extension/

# Load the extension in your database
psql -d your_database -c "CREATE EXTENSION user_contact;"
```

## Usage

### Setting Contact Information

Before creating a user, you must set their contact information:

```sql
-- Set contact info for the user you're about to create
SELECT set_user_contact_info('john.doe@company.com', '+1-555-123-4567');

-- Now create the user (contact info will be automatically stored)
CREATE USER john_doe WITH PASSWORD 'secure_password';
```

### Retrieving Contact Information

```sql
-- Get contact info for a specific user
SELECT * FROM get_user_contact('john_doe');
-- Returns: (email, phone, created_at, updated_at)
```

### Administrative Functions

```sql
-- Update contact info (superuser only)
SELECT update_user_contact('john_doe', 'new.email@company.com', '+1-555-987-6543');

-- List all user contacts (superuser only)
SELECT * FROM list_all_user_contacts();

-- Clear pending contact info (if needed)
SELECT clear_pending_contact_info();
```

## API Reference

### Public Functions

#### `set_user_contact_info(email text, phone text) → text`
- **Purpose**: Store email and phone in session memory for the next CREATE USER command
- **Access**: Available to all users
- **Validation**: Checks email format (contains @) and phone length (≥7 chars)
- **Returns**: Success message

#### `get_user_contact(username text) → record`
- **Purpose**: Retrieve contact information for a specific user
- **Access**: Available to all users
- **Returns**: Record with (email, phone, created_at, updated_at)
- **Error**: Throws exception if user not found

#### `clear_pending_contact_info() → text`
- **Purpose**: Clear any pending contact information from session
- **Access**: Available to all users
- **Returns**: Confirmation message

### Superuser-Only Functions

#### `update_user_contact(username text, email text, phone text) → void`
- **Purpose**: Update existing user's contact information
- **Access**: Superuser only
- **Validation**: Same as set_user_contact_info
- **Error**: Throws exception if user not found

#### `list_all_user_contacts() → SETOF user_contact_info`
- **Purpose**: Return all contact information records
- **Access**: Superuser only
- **Returns**: All rows from the contact table

## Database Schema

```sql
CREATE TABLE user_contact_info (
    username    VARCHAR(63) PRIMARY KEY,
    email       VARCHAR(255) NOT NULL 
                  CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    phone       VARCHAR(20) NOT NULL
                  CHECK (length(phone) >= 7),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

## Security Model

### Row-Level Security (RLS)
- Direct table access is completely blocked via RLS policy
- All access must go through the provided API functions
- Even superusers cannot directly query the table

### Permissions
- Base table has all privileges revoked from all users
- Only specific functions are granted execute permissions
- Administrative functions require superuser privileges

### Data Protection
- Contact information is stored securely with proper constraints
- SQL injection protection through parameterized queries
- Input validation at multiple levels

## Workflow

1. **Preparation**: Call `set_user_contact_info()` with email and phone
2. **Validation**: Extension validates format and stores in session memory
3. **User Creation**: Execute `CREATE USER` command
4. **Interception**: ProcessUtility hook intercepts the command
5. **Verification**: Hook checks that contact info was set
6. **Execution**: User creation proceeds normally
7. **Storage**: Contact info is automatically inserted into the table
8. **Cleanup**: Session contact info is cleared

## Error Handling

The extension provides clear error messages for common issues:

- **Missing Contact Info**: "Contact information must be set before creating user"
- **Invalid Email**: "Invalid email format: [email]"
- **Short Phone**: "Phone number too short: [phone]"
- **User Not Found**: "No contact info found for user: [username]"
- **Permission Denied**: "must be superuser to update user contact info"

## Logging

The extension provides comprehensive logging at LOG level:
- Function calls and parameters
- Hook interceptions
- SQL query executions
- Success/failure notifications

Enable PostgreSQL logging to see detailed operation traces.

## Troubleshooting

### Common Issues

**Extension won't load**
```sql
-- Check if extension is installed
SELECT * FROM pg_extension WHERE extname = 'user_contact';

-- Check for error messages in PostgreSQL logs
SHOW log_destination;
```

**CREATE USER fails with contact error**
```sql
-- Verify contact info is set
SELECT clear_pending_contact_info();
SELECT set_user_contact_info('valid@email.com', '1234567890');
CREATE USER test_user;
```

**Cannot access contact information**
```sql
-- Remember: direct table access is blocked
-- Use the API functions instead
SELECT * FROM get_user_contact('username');
```

## Development

### Building from Source

The extension requires:
- PostgreSQL server development headers
- Access to PostgreSQL's SPI (Server Programming Interface)
- Standard C development tools

### Extension Structure

```
user_contact/
├── user_contact.c           # Main C implementation
├── user_contact--1.0.sql    # SQL installation script
├── user_contact.control     # Extension control file
├── Makefile                 # Build configuration
└── README.md               # This file
```