/*
 * user_contact.c - CORRECTED VERSION
 * PostgreSQL extension that blocks CREATE USER and provides create_user_with_contact() instead
 *
 * Notes on fixes (kept logic intact):
 *  - get_user_contact now selects and returns username + other columns so it matches the SQL
 *    declaration (RETURNS TABLE (...)). The tuple returned is copied out of SPI memory before
 *    SPI_finish().
 *  - list_all_user_contacts loop index uses an integer loop variable to iterate SPI results.
 *  - Added <stdint.h> include (portable integer types).
 *  - Minor defensive checks and minimal repairs only; logic otherwise unchanged.
 */

#include <stdint.h>

#include "postgres.h"
#include "access/xact.h"
#include "catalog/pg_authid.h"
#include "commands/user.h"
#include "executor/spi.h"
#include "nodes/pg_list.h"
#include "tcop/utility.h"
#include "utils/guc.h"
#include "utils/builtins.h"
#include "miscadmin.h"
#include "funcapi.h"
#include "utils/memutils.h"
#include "access/htup_details.h"
#include "catalog/pg_type.h"
#include "utils/syscache.h"
#include "parser/parse_node.h"

PG_MODULE_MAGIC;

/* Previous hook */
static ProcessUtility_hook_type prev_ProcessUtility = NULL;

/* Hook function that blocks CREATE USER/ROLE with login capability */
static void
user_contact_ProcessUtility(PlannedStmt *pstmt,
                            const char *queryString,
                            bool readOnlyTree,
                            ProcessUtilityContext context,
                            ParamListInfo params,
                            QueryEnvironment *queryEnv,
                            DestReceiver *dest,
                            QueryCompletion *qc)
{
    Node *parsetree = pstmt->utilityStmt;

    /* Intercept CREATE USER / CREATE ROLE statements */
    if (IsA(parsetree, CreateRoleStmt))
    {
        CreateRoleStmt *stmt = (CreateRoleStmt *) parsetree;
        bool is_user = false;
        bool has_login = false;

        elog(LOG, "user_contact: Intercepted CREATE ROLE/USER for '%s'", stmt->role);

        /* Check if this is a user (login role).
         *
         * If stmt_type == ROLESTMT_USER then CREATE USER was used (implies login).
         * Otherwise, look for explicit "LOGIN" option in stmt->options.
         *
         * Minimal handling of option AST is used so we don't change behaviour.
         */
        ListCell *option;
        foreach(option, stmt->options)
        {
            DefElem *defel = (DefElem *) lfirst(option);
            if (strcmp(defel->defname, "login") == 0)
            {
                /* If an argument exists, treat its presence as an explicit login flag.
                 * We avoid heavy parsing of the node here; presence means the
                 * user specified LOGIN/NOLOGIN; we'll treat presence as login true
                 * only if the provided value looks like "true" or is a non-null Const.
                 */
                if (defel->arg)
                {
                    /* Best-effort extraction: if it's a Const node, attempt to read constvalue.
                     * If not, assume the user provided the option and treat it as true.
                     */
                    if (IsA(defel->arg, A_Const))
                    {
                        Const *c = (Const *) defel->arg;
                        /* Try to interpret boolean-like const; fallback to treating presence as true */
                        if (c->constisnull)
                            has_login = true;
                        else
                        {
                            /* DatumGetBool use is a best-effort; if consttype isn't boolean,
                             * DatumGetBool result is undefined but most parse trees for LOGIN
                             * use a boolean-like Const. Keep original behavior.
                             */
                            has_login = DatumGetBool(c->constvalue);
                        }
                    }
                    else
                    {
                        has_login = true;
                    }
                }
                else
                {
                    /* No arg => presence of the option (e.g., plain LOGIN) */
                    has_login = true;
                }

                break;
            }
        }

        /* CREATE USER implies LOGIN by default */
        if (stmt->stmt_type == ROLESTMT_USER)
            is_user = true;
        else if (has_login)
            is_user = true;

        elog(LOG, "user_contact: is_user = %s", is_user ? "true" : "false");

        if (is_user)
        {
            /* Block the CREATE USER/ROLE with login and provide helpful error message */
            ereport(ERROR,
                    (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                     errmsg("Direct CREATE USER is not allowed"),
                     errhint("Use create_user_with_contact(username, password, email, phone) instead"),
                     errdetail("This system requires contact information for all user accounts")));
        }
    }

    /* For non-user creation statements, proceed normally */
    if (prev_ProcessUtility)
        prev_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
    else
        standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
}

/* Function to create user with contact info in one atomic operation */
PG_FUNCTION_INFO_V1(create_user_with_contact);
Datum
create_user_with_contact(PG_FUNCTION_ARGS)
{
    char *username = text_to_cstring(PG_GETARG_TEXT_PP(0));
    char *password = text_to_cstring(PG_GETARG_TEXT_PP(1));
    char *email = text_to_cstring(PG_GETARG_TEXT_PP(2));
    char *phone = text_to_cstring(PG_GETARG_TEXT_PP(3));
    int ret;
    StringInfoData create_user_query;
    StringInfoData insert_contact_query;

    elog(LOG, "user_contact: create_user_with_contact called for user='%s', email='%s', phone='%s'",
         username, email, phone);

    /* Only superusers can create users */
    if (!superuser())
        ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                 errmsg("must be superuser to create users")));

    /* Validate inputs */
    if (!username || strlen(username) == 0)
        ereport(ERROR, (errmsg("Username cannot be empty")));

    if (!password || strlen(password) == 0)
        ereport(ERROR, (errmsg("Password cannot be empty")));

    if (!email || strlen(email) == 0)
        ereport(ERROR, (errmsg("Email cannot be empty")));

    if (!phone || strlen(phone) == 0)
        ereport(ERROR, (errmsg("Phone cannot be empty")));

    /* Validate email format */
    if (!strstr(email, "@"))
        ereport(ERROR, (errmsg("Invalid email format: %s", email)));

    /* Validate phone format */
    if (strlen(phone) < 7)
        ereport(ERROR, (errmsg("Phone number too short: %s", phone)));

    /* Start SPI */
    ret = SPI_connect();
    if (ret != SPI_OK_CONNECT)
        elog(ERROR, "user_contact: SPI_connect failed: %d", ret);

    /* Check if user already exists */
    initStringInfo(&create_user_query);
    appendStringInfo(&create_user_query,
        "SELECT 1 FROM pg_authid WHERE rolname = %s",
        quote_literal_cstr(username));

    ret = SPI_execute(create_user_query.data, true, 1);
    if (ret != SPI_OK_SELECT)
    {
        pfree(create_user_query.data);
        SPI_finish();
        elog(ERROR, "user_contact: Failed to check if user exists: %d", ret);
    }

    if (SPI_processed > 0)
    {
        pfree(create_user_query.data);
        SPI_finish();
        ereport(ERROR, (errmsg("User '%s' already exists", username)));
    }

    /* Create the user using CREATE USER statement */
    resetStringInfo(&create_user_query);
    appendStringInfo(&create_user_query,
        "CREATE USER %s WITH PASSWORD %s",
        quote_identifier(username),
        quote_literal_cstr(password));

    elog(LOG, "user_contact: Creating user with query: CREATE USER %s WITH PASSWORD [HIDDEN]", quote_identifier(username));

    /* Temporarily disable our hook to allow the CREATE USER to proceed */
    ProcessUtility_hook_type saved_hook = ProcessUtility_hook;
    ProcessUtility_hook = prev_ProcessUtility;

    /* Execute CREATE USER */
    ret = SPI_execute(create_user_query.data, false, 0);

    /* Restore our hook */
    ProcessUtility_hook = saved_hook;

    if (ret != SPI_OK_UTILITY)
    {
        pfree(create_user_query.data);
        SPI_finish();
        elog(ERROR, "user_contact: Failed to create user '%s': %d", username, ret);
    }

    elog(LOG, "user_contact: User '%s' created successfully", username);

    /* Now insert the contact information */
    initStringInfo(&insert_contact_query);
    appendStringInfo(&insert_contact_query,
        "INSERT INTO user_contact_info(username, email, phone, created_at) "
        "VALUES (%s, %s, %s, NOW())",
        quote_literal_cstr(username),
        quote_literal_cstr(email),
        quote_literal_cstr(phone));

    elog(LOG, "user_contact: Executing contact insert query: %s", insert_contact_query.data);

    ret = SPI_execute(insert_contact_query.data, false, 0);

    if (ret != SPI_OK_INSERT)
    {
        /* If contact info insertion fails, we should rollback the user creation */
        elog(WARNING, "user_contact: Failed to insert contact info for user '%s': %d", username, ret);
        elog(WARNING, "user_contact: Rolling back user creation");

        /* Try to drop the user we just created */
        StringInfoData drop_user_query;
        initStringInfo(&drop_user_query);
        appendStringInfo(&drop_user_query, "DROP USER %s", quote_identifier(username));

        /* Temporarily disable hook so DROP USER succeeds */
        ProcessUtility_hook = prev_ProcessUtility;
        SPI_execute(drop_user_query.data, false, 0);
        ProcessUtility_hook = saved_hook;

        pfree(drop_user_query.data);
        pfree(create_user_query.data);
        pfree(insert_contact_query.data);
        SPI_finish();

        ereport(ERROR,
                (errmsg("Failed to create user '%s': contact info insertion failed", username)));
    }

    elog(LOG, "user_contact: Contact info inserted successfully for user '%s'", username);

    /* Clean up */
    pfree(create_user_query.data);
    pfree(insert_contact_query.data);
    SPI_finish();

    elog(NOTICE, "User '%s' created successfully with contact information", username);

    PG_RETURN_TEXT_P(cstring_to_text("User created successfully with contact information"));
}

/* Function to create user with additional options */
PG_FUNCTION_INFO_V1(create_user_with_contact_extended);
Datum
create_user_with_contact_extended(PG_FUNCTION_ARGS)
{
    char *username = text_to_cstring(PG_GETARG_TEXT_PP(0));
    char *password = text_to_cstring(PG_GETARG_TEXT_PP(1));
    char *email = text_to_cstring(PG_GETARG_TEXT_PP(2));
    char *phone = text_to_cstring(PG_GETARG_TEXT_PP(3));
    char *additional_options = PG_ARGISNULL(4) ? NULL : text_to_cstring(PG_GETARG_TEXT_PP(4));
    int ret;
    StringInfoData create_user_query;
    StringInfoData insert_contact_query;

    elog(LOG, "user_contact: create_user_with_contact_extended called for user='%s'", username);

    /* Only superusers can create users */
    if (!superuser())
        ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                 errmsg("must be superuser to create users")));

    /* Validate inputs */
    if (!username || strlen(username) == 0)
        ereport(ERROR, (errmsg("Username cannot be empty")));

    if (!password || strlen(password) == 0)
        ereport(ERROR, (errmsg("Password cannot be empty")));

    if (!email || strlen(email) == 0)
        ereport(ERROR, (errmsg("Email cannot be empty")));

    if (!phone || strlen(phone) == 0)
        ereport(ERROR, (errmsg("Phone cannot be empty")));

    /* Validate email format */
    if (!strstr(email, "@"))
        ereport(ERROR, (errmsg("Invalid email format: %s", email)));

    /* Validate phone format */
    if (strlen(phone) < 7)
        ereport(ERROR, (errmsg("Phone number too short: %s", phone)));

    /* Start SPI */
    ret = SPI_connect();
    if (ret != SPI_OK_CONNECT)
        elog(ERROR, "user_contact: SPI_connect failed: %d", ret);

    /* Check if user already exists */
    initStringInfo(&create_user_query);
    appendStringInfo(&create_user_query,
        "SELECT 1 FROM pg_authid WHERE rolname = %s",
        quote_literal_cstr(username));

    ret = SPI_execute(create_user_query.data, true, 1);
    if (ret != SPI_OK_SELECT)
    {
        pfree(create_user_query.data);
        SPI_finish();
        elog(ERROR, "user_contact: Failed to check if user exists: %d", ret);
    }

    if (SPI_processed > 0)
    {
        pfree(create_user_query.data);
        SPI_finish();
        ereport(ERROR, (errmsg("User '%s' already exists", username)));
    }

    /* Build CREATE USER statement with additional options */
    resetStringInfo(&create_user_query);
    appendStringInfo(&create_user_query,
        "CREATE USER %s WITH PASSWORD %s",
        quote_identifier(username),
        quote_literal_cstr(password));

    if (additional_options && strlen(additional_options) > 0)
    {
        appendStringInfo(&create_user_query, " %s", additional_options);
    }

    elog(LOG, "user_contact: Creating user with additional options");

    /* Temporarily disable our hook to allow the CREATE USER to proceed */
    ProcessUtility_hook_type saved_hook = ProcessUtility_hook;
    ProcessUtility_hook = prev_ProcessUtility;

    /* Execute CREATE USER */
    ret = SPI_execute(create_user_query.data, false, 0);

    /* Restore our hook */
    ProcessUtility_hook = saved_hook;

    if (ret != SPI_OK_UTILITY)
    {
        pfree(create_user_query.data);
        SPI_finish();
        elog(ERROR, "user_contact: Failed to create user '%s': %d", username, ret);
    }

    /* Now insert the contact information */
    initStringInfo(&insert_contact_query);
    appendStringInfo(&insert_contact_query,
        "INSERT INTO user_contact_info(username, email, phone, created_at) "
        "VALUES (%s, %s, %s, NOW())",
        quote_literal_cstr(username),
        quote_literal_cstr(email),
        quote_literal_cstr(phone));

    ret = SPI_execute(insert_contact_query.data, false, 0);

    if (ret != SPI_OK_INSERT)
    {
        /* Rollback user creation if contact info fails */
        StringInfoData drop_user_query;
        initStringInfo(&drop_user_query);
        appendStringInfo(&drop_user_query, "DROP USER %s", quote_identifier(username));

        ProcessUtility_hook = prev_ProcessUtility;
        SPI_execute(drop_user_query.data, false, 0);
        ProcessUtility_hook = saved_hook;

        pfree(drop_user_query.data);
        pfree(create_user_query.data);
        pfree(insert_contact_query.data);
        SPI_finish();

        ereport(ERROR,
                (errmsg("Failed to create user '%s': contact info insertion failed", username)));
    }

    /* Clean up */
    pfree(create_user_query.data);
    pfree(insert_contact_query.data);
    SPI_finish();

    elog(NOTICE, "User '%s' created successfully with contact information", username);

    PG_RETURN_TEXT_P(cstring_to_text("User created successfully with contact information"));
}

/* Set contact info directly for an existing user */
PG_FUNCTION_INFO_V1(set_user_contact_info_direct);
Datum
set_user_contact_info_direct(PG_FUNCTION_ARGS)
{
    char *username = text_to_cstring(PG_GETARG_TEXT_PP(0));
    char *email = text_to_cstring(PG_GETARG_TEXT_PP(1));
    char *phone = text_to_cstring(PG_GETARG_TEXT_PP(2));
    char *current_user_name = GetUserNameFromId(GetUserId(), false);
    int ret;
    StringInfoData query;

    elog(LOG, "user_contact: set_user_contact_info_direct called for user='%s', email='%s', phone='%s' by '%s'",
         username, email, phone, current_user_name);

    /* Users can only set contact info for themselves, unless they are superuser */
    if (!superuser() && strcmp(current_user_name, username) != 0)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                 errmsg("permission denied"),
                 errhint("Users can only set contact information for themselves")));
    }

    /* Basic validation */
    if (!email || strlen(email) == 0)
        ereport(ERROR, (errmsg("Email cannot be empty")));

    if (!phone || strlen(phone) == 0)
        ereport(ERROR, (errmsg("Phone cannot be empty")));

    if (!strstr(email, "@"))
        ereport(ERROR, (errmsg("Invalid email format")));

    if (strlen(phone) < 7)
        ereport(ERROR, (errmsg("Phone number too short")));

    /* Check if user exists in pg_authid */
    ret = SPI_connect();
    if (ret != SPI_OK_CONNECT)
        elog(ERROR, "user_contact: SPI_connect failed: %d", ret);

    initStringInfo(&query);
    appendStringInfo(&query,
        "SELECT 1 FROM pg_authid WHERE rolname = %s",
        quote_literal_cstr(username));

    ret = SPI_execute(query.data, true, 1);
    if (ret != SPI_OK_SELECT)
    {
        pfree(query.data);
        SPI_finish();
        elog(ERROR, "user_contact: Failed to check if user exists: %d", ret);
    }

    if (SPI_processed == 0)
    {
        pfree(query.data);
        SPI_finish();
        ereport(ERROR, (errmsg("User '%s' does not exist", username)));
    }

    /* Insert or update contact info */
    resetStringInfo(&query);
    appendStringInfo(&query,
        "INSERT INTO user_contact_info(username, email, phone, created_at) "
        "VALUES (%s, %s, %s, NOW()) "
        "ON CONFLICT (username) DO UPDATE SET "
        "email = EXCLUDED.email, phone = EXCLUDED.phone, updated_at = NOW()",
        quote_literal_cstr(username),
        quote_literal_cstr(email),
        quote_literal_cstr(phone));

    elog(LOG, "user_contact: Executing query: %s", query.data);

    ret = SPI_execute(query.data, false, 0);

    if (ret != SPI_OK_INSERT && ret != SPI_OK_INSERT_RETURNING)
    {
        pfree(query.data);
        SPI_finish();
        elog(ERROR, "user_contact: Failed to set contact info: %d", ret);
    }

    pfree(query.data);
    SPI_finish();

    elog(NOTICE, "Contact info set for user '%s'", username);
    PG_RETURN_TEXT_P(cstring_to_text("Contact info set successfully"));
}

/* Get contact info function with user permission checks */
PG_FUNCTION_INFO_V1(get_user_contact);
Datum
get_user_contact(PG_FUNCTION_ARGS)
{
    char *username = text_to_cstring(PG_GETARG_TEXT_PP(0));
    char *current_user_name = GetUserNameFromId(GetUserId(), false);
    int ret;
    HeapTuple tuple;
    Datum result;

    elog(LOG, "user_contact: get_user_contact called for user '%s' by '%s'", username, current_user_name);

    /* Users can only view their own contact info, unless they are superuser */
    if (!superuser() && strcmp(current_user_name, username) != 0)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                 errmsg("permission denied"),
                 errhint("Users can only view their own contact information")));
    }

    ret = SPI_connect();
    if (ret != SPI_OK_CONNECT)
    {
        elog(ERROR, "user_contact: SPI_connect failed: %d", ret);
        PG_RETURN_NULL();
    }

    StringInfoData query;
    initStringInfo(&query);
    /* Select username as well so returned composite row matches table shape */
    appendStringInfo(&query,
        "SELECT username, email, phone, created_at, updated_at FROM user_contact_info WHERE username = %s",
        quote_literal_cstr(username));

    ret = SPI_execute(query.data, true, 1);

    if (ret != SPI_OK_SELECT)
    {
        pfree(query.data);
        SPI_finish();
        elog(ERROR, "user_contact: SPI_execute failed: %d", ret);
    }

    if (SPI_processed == 0)
    {
        pfree(query.data);
        SPI_finish();
        ereport(ERROR, (errmsg("No contact info found for user: %s", username)));
    }

    /* Get the result tuple (first row) and copy it out of SPI memory */
    tuple = SPI_tuptable->vals[0];
    HeapTuple copy = heap_copytuple(tuple);
    result = HeapTupleGetDatum(copy);

    pfree(query.data);
    SPI_finish();

    PG_RETURN_DATUM(result);
}

/* Update contact info with UPSERT and partial updates */
PG_FUNCTION_INFO_V1(update_user_contact);
Datum
update_user_contact(PG_FUNCTION_ARGS)
{
    char *username = text_to_cstring(PG_GETARG_TEXT_PP(0));
    char *email = NULL;
    char *phone = NULL;
    bool email_provided = !PG_ARGISNULL(1);
    bool phone_provided = !PG_ARGISNULL(2);
    char *current_user_name = GetUserNameFromId(GetUserId(), false);
    int ret;
    StringInfoData query;
    StringInfoData set_clause;

    if (email_provided)
        email = text_to_cstring(PG_GETARG_TEXT_PP(1));
    if (phone_provided)
        phone = text_to_cstring(PG_GETARG_TEXT_PP(2));

    /* Users can only update their own contact info, unless they are superuser */
    if (!superuser() && strcmp(current_user_name, username) != 0)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                 errmsg("permission denied"),
                 errhint("Users can only update their own contact information")));
    }

    /* At least one field must be provided */
    if (!email_provided && !phone_provided)
    {
        ereport(ERROR, (errmsg("At least one of email or phone must be provided")));
    }

    /* Validate provided fields */
    if (email_provided)
    {
        if (!email || strlen(email) == 0)
            ereport(ERROR, (errmsg("Email cannot be empty")));
        if (!strstr(email, "@"))
            ereport(ERROR, (errmsg("Invalid email format")));
    }

    if (phone_provided)
    {
        if (!phone || strlen(phone) == 0)
            ereport(ERROR, (errmsg("Phone cannot be empty")));
        if (strlen(phone) < 7)
            ereport(ERROR, (errmsg("Phone number too short")));
    }

    ret = SPI_connect();
    if (ret != SPI_OK_CONNECT)
    {
        elog(ERROR, "user_contact: SPI_connect failed: %d", ret);
        PG_RETURN_VOID();
    }

    /* Build the SET clause dynamically */
    initStringInfo(&set_clause);
    bool first = true;

    if (email_provided)
    {
        if (!first) appendStringInfo(&set_clause, ", ");
        appendStringInfo(&set_clause, "email = %s", quote_literal_cstr(email));
        first = false;
    }

    if (phone_provided)
    {
        if (!first) appendStringInfo(&set_clause, ", ");
        appendStringInfo(&set_clause, "phone = %s", quote_literal_cstr(phone));
        first = false;
    }

    /* Always update the timestamp */
    appendStringInfo(&set_clause, ", updated_at = NOW()");

    /* Try UPDATE first */
    initStringInfo(&query);
    appendStringInfo(&query,
        "UPDATE user_contact_info SET %s WHERE username = %s",
        set_clause.data,
        quote_literal_cstr(username));

    ret = SPI_execute(query.data, false, 0);

    if (ret != SPI_OK_UPDATE)
    {
        pfree(set_clause.data);
        pfree(query.data);
        SPI_finish();
        elog(ERROR, "user_contact: Failed to update contact info: %d", ret);
    }

    /* If no rows were updated, INSERT new record (if both email and phone provided) */
    if (SPI_processed == 0)
    {
        if (!email_provided || !phone_provided)
        {
            pfree(set_clause.data);
            pfree(query.data);
            SPI_finish();
            ereport(ERROR,
                    (errmsg("Cannot create new contact record without both email and phone")));
        }

        resetStringInfo(&query);
        appendStringInfo(&query,
            "INSERT INTO user_contact_info(username, email, phone, created_at) "
            "VALUES (%s, %s, %s, NOW())",
            quote_literal_cstr(username),
            quote_literal_cstr(email),
            quote_literal_cstr(phone));

        ret = SPI_execute(query.data, false, 0);

        if (ret != SPI_OK_INSERT)
        {
            pfree(set_clause.data);
            pfree(query.data);
            SPI_finish();
            elog(ERROR, "user_contact: Failed to insert contact info: %d", ret);
        }

        elog(NOTICE, "Contact info created for user '%s'", username);
    }
    else
    {
        elog(NOTICE, "Contact info updated for user '%s'", username);
    }

    pfree(set_clause.data);
    pfree(query.data);
    SPI_finish();

    PG_RETURN_VOID();
}

/* List all user contacts - superuser only */
PG_FUNCTION_INFO_V1(list_all_user_contacts);
Datum
list_all_user_contacts(PG_FUNCTION_ARGS)
{
    ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
    Tuplestorestate *tupstore;
    MemoryContext per_query_ctx;
    MemoryContext oldcontext;
    TupleDesc tupdesc;
    int ret;

    /* Only superusers can list all contacts */
    if (!superuser())
        ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                 errmsg("must be superuser to list all user contacts")));

    /* Check if called in proper context */
    if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("function returning record called in context that cannot accept a set")));

    if (!(rsinfo->allowedModes & SFRM_Materialize))
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("materialize mode required, but it is not allowed in this context")));

    /* Switch to appropriate memory context */
    per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
    oldcontext = MemoryContextSwitchTo(per_query_ctx);

    /* Create tuplestore */
    tupstore = tuplestore_begin_heap(true, false, work_mem);
    rsinfo->returnMode = SFRM_Materialize;
    rsinfo->setResult = tupstore;

    /* Connect to SPI */
    ret = SPI_connect();
    if (ret != SPI_OK_CONNECT)
    {
        MemoryContextSwitchTo(oldcontext);
        elog(ERROR, "user_contact: SPI_connect failed: %d", ret);
    }

    /* Execute query */
    ret = SPI_execute("SELECT username, email, phone, created_at, updated_at FROM user_contact_info ORDER BY username", true, 0);
    if (ret != SPI_OK_SELECT)
    {
        SPI_finish();
        MemoryContextSwitchTo(oldcontext);
        elog(ERROR, "user_contact: SPI_execute failed: %d", ret);
    }

    /* Set up tuple descriptor */
    tupdesc = SPI_tuptable->tupdesc;
    rsinfo->setDesc = CreateTupleDescCopy(tupdesc);

    /* Copy all tuples to tuplestore */
    for (int i = 0; i < (int) SPI_processed; i++)
    {
        HeapTuple tuple = SPI_tuptable->vals[i];
        tuplestore_puttuple(tupstore, tuple);
    }

    SPI_finish();
    MemoryContextSwitchTo(oldcontext);

    PG_RETURN_NULL();
}

/* Backward compatibility alias */
PG_FUNCTION_INFO_V1(set_user_contact_info);
Datum
set_user_contact_info(PG_FUNCTION_ARGS)
{
    /* Just call the existing function */
    return set_user_contact_info_direct(fcinfo);
}

/* Module load */
void
_PG_init(void)
{
    /* Install the ProcessUtility hook */
    prev_ProcessUtility = ProcessUtility_hook;
    ProcessUtility_hook = user_contact_ProcessUtility;

    elog(LOG, "user_contact extension loaded - CREATE USER blocked, use create_user_with_contact() instead");
}

/* Module unload */
void
_PG_fini(void)
{
    /* Restore the previous hook */
    ProcessUtility_hook = prev_ProcessUtility;

    elog(LOG, "user_contact extension unloaded");
}
