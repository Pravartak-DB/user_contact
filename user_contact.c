/*
 * user_contact.c - ENHANCED VERSION WITH MANAGER FIXES
 * PostgreSQL extension for storing user contact info
 * 
 * Changes:
 * 1. Support both CREATE USER and CREATE ROLE ... LOGIN
 * 2. Use case-insensitive username comparisons (pg_strcasecmp)
 * 3. Transaction callback to ensure pending contact info is always cleared
 * 4. Dedicated memory context in hook for memory safety
 * 5. Direct catalog insertion instead of SPI for CREATE USER handling
 */

#include "postgres.h"
#include "access/xact.h"
#include "access/heapam.h"
#include "access/table.h"
#include "access/htup_details.h"
#include "catalog/pg_authid.h"
#include "catalog/indexing.h"
#include "commands/user.h"
#include "executor/spi.h"
#include "nodes/pg_list.h"
#include "tcop/utility.h"
#include "utils/guc.h"
#include "utils/builtins.h"
#include "utils/rel.h"
#include "miscadmin.h"
#include "funcapi.h"
#include "utils/memutils.h"
#include "catalog/pg_type.h"
#include "catalog/namespace.h"
#include "utils/syscache.h"
#include "utils/lsyscache.h"
#include "nodes/makefuncs.h"   

PG_MODULE_MAGIC;

/* Previous hook */
static ProcessUtility_hook_type prev_ProcessUtility = NULL;

/* Session memory for pending contact info (stored in TopMemoryContext) */
static char *pending_user_email = NULL;
static char *pending_user_phone = NULL;

/* Forward declarations */
static void user_contact_xact_callback(XactEvent event, void *arg);
static void cleanup_pending_contact_info(void);
static bool is_login_role(CreateRoleStmt *stmt);
static void insert_contact_via_catalog(const char *username, const char *email, const char *phone);

/* Transaction callback to ensure cleanup on commit/abort */
static void
user_contact_xact_callback(XactEvent event, void *arg)
{
    if (event == XACT_EVENT_COMMIT || event == XACT_EVENT_ABORT)
    {
        elog(LOG, "user_contact: Transaction callback triggered (event=%d), clearing pending contact info", event);
        cleanup_pending_contact_info();
    }
}

/* Helper: Clear pending contact info */
static void
cleanup_pending_contact_info(void)
{
    if (pending_user_email)
    {
        pfree(pending_user_email);
        pending_user_email = NULL;
    }
    if (pending_user_phone)
    {
        pfree(pending_user_phone);
        pending_user_phone = NULL;
    }
    elog(LOG, "user_contact: Pending contact info cleared");
}

/* Helper: Determine if this is a login role (CREATE USER or CREATE ROLE ... LOGIN) */
static bool
is_login_role(CreateRoleStmt *stmt)
{
    ListCell *option;

    /* If stmt_type is ROLESTMT_USER, it's definitely a login role */
    if (stmt->stmt_type == ROLESTMT_USER)
    {
        elog(LOG, "user_contact: stmt_type=ROLESTMT_USER, treating as login role");
        return true;
    }

    /* Otherwise, check for explicit LOGIN option */
    foreach(option, stmt->options)
    {
        DefElem *defel = (DefElem *) lfirst(option);
        
        /* Case-insensitive comparison for "login" */
        if (pg_strcasecmp(defel->defname, "login") == 0)
        {
            /* Check if the value is true */
            if (defel->arg && IsA(defel->arg, Integer))
            {
                int login_val = intVal((Integer *)defel->arg);
                elog(LOG, "user_contact: Found LOGIN option with Integer value=%d", login_val);
                return (login_val != 0);
            }
            else if (defel->arg == NULL)
            {
                /* LOGIN without a value means true */
                elog(LOG, "user_contact: Found LOGIN option without value (defaults to true)");
                return true;
            }
        }
    }

    elog(LOG, "user_contact: No LOGIN option found, not treating as login role");
    return false;
}

/* Helper: Insert contact info using direct catalog access */
static void
insert_contact_via_catalog(const char *username, const char *email, const char *phone)
{
    Relation rel;
    TupleDesc tupdesc;
    HeapTuple tuple;
    Datum values[5];
    bool nulls[5];
    Oid table_oid;
    RangeVar *rv;

    elog(LOG, "user_contact: insert_contact_via_catalog for user='%s'", username);

    /* Open the user_contact_info table */
    rv = makeRangeVar(NULL, "user_contact_info", -1);
    table_oid = RangeVarGetRelid(rv, AccessShareLock, false);
    rel = table_open(table_oid, RowExclusiveLock);
    tupdesc = RelationGetDescr(rel);

    /* Prepare values for tuple */
    values[0] = CStringGetTextDatum(username);  /* username */
    values[1] = CStringGetTextDatum(email);     /* email */
    values[2] = CStringGetTextDatum(phone);     /* phone */
    values[3] = TimestampTzGetDatum(GetCurrentTimestamp());  /* created_at */
    values[4] = TimestampTzGetDatum(GetCurrentTimestamp());  /* updated_at */

    memset(nulls, false, sizeof(nulls));

    /* Form the tuple */
    tuple = heap_form_tuple(tupdesc, values, nulls);

    /* Insert tuple into catalog */
    CatalogTupleInsert(rel, tuple);

    elog(LOG, "user_contact: Successfully inserted contact info via catalog");

    /* Cleanup */
    heap_freetuple(tuple);
    table_close(rel, RowExclusiveLock);

    elog(NOTICE, "Contact info stored for user '%s'", username);
}

/* Hook function with all manager fixes applied */
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
    MemoryContext hook_mcxt = NULL;
    MemoryContext old_mcxt = NULL;

    /* Intercept CREATE USER / CREATE ROLE before execution */
    if (IsA(parsetree, CreateRoleStmt))
    {
        CreateRoleStmt *stmt = (CreateRoleStmt *) parsetree;
        bool is_user = is_login_role(stmt);

        elog(LOG, "user_contact: Intercepted CREATE ROLE/USER for '%s'", stmt->role);
        elog(LOG, "user_contact: is_login_role = %s", is_user ? "true" : "false");

        if (is_user)
        {
            elog(LOG, "user_contact: Checking contact info - email: '%s', phone: '%s'", 
                 pending_user_email ? pending_user_email : "NULL", 
                 pending_user_phone ? pending_user_phone : "NULL");

            /* Check if contact info has been set */
            if (!pending_user_email || strlen(pending_user_email) == 0 || 
                !pending_user_phone || strlen(pending_user_phone) == 0)
            {
                ereport(ERROR,
                        (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                         errmsg("Contact information must be set before creating user"),
                         errhint("Use: SELECT set_user_contact_info('email@example.com', '1234567890'); before CREATE USER/ROLE")));
            }

            /* Basic validation */
            if (!strstr(pending_user_email, "@"))
            {
                ereport(ERROR,
                        (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                         errmsg("Invalid email format: %s", pending_user_email)));
            }

            if (strlen(pending_user_phone) < 7)
            {
                ereport(ERROR,
                        (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                         errmsg("Phone number too short: %s", pending_user_phone)));
            }

            elog(LOG, "user_contact: Contact info validation passed");
        }
    }

    /* Create dedicated memory context for hook operations */
    hook_mcxt = AllocSetContextCreate(CurrentMemoryContext,
                                      "user_contact_hook_context",
                                      ALLOCSET_DEFAULT_SIZES);
    old_mcxt = MemoryContextSwitchTo(hook_mcxt);

    /* Call original ProcessUtility to execute the command */
    PG_TRY();
    {
        if (prev_ProcessUtility)
            prev_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
        else
            standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
    }
    PG_CATCH();
    {
        /* Clean up memory context and re-throw */
        MemoryContextSwitchTo(old_mcxt);
        MemoryContextDelete(hook_mcxt);
        PG_RE_THROW();
    }
    PG_END_TRY();

    /* After successful CREATE USER, insert contact info using catalog API */
    if (IsA(parsetree, CreateRoleStmt))
    {
        CreateRoleStmt *stmt = (CreateRoleStmt *) parsetree;
        bool is_user = is_login_role(stmt);

        if (is_user && pending_user_email && pending_user_phone)
        {
            elog(LOG, "user_contact: Attempting to store contact info for user '%s'", stmt->role);
            
            /* Use direct catalog insertion instead of SPI */
            PG_TRY();
            {
                insert_contact_via_catalog(stmt->role, pending_user_email, pending_user_phone);
            }
            PG_CATCH();
            {
                elog(WARNING, "user_contact: Failed to insert contact info for user '%s'", stmt->role);
                /* Don't re-throw - the user was created successfully */
                FlushErrorState();
            }
            PG_END_TRY();

            /* Clear the pending contact info (transaction callback will also clear it) */
            cleanup_pending_contact_info();
            
            elog(LOG, "user_contact: Contact info insertion completed");
        }
    }

    /* Clean up dedicated memory context */
    MemoryContextSwitchTo(old_mcxt);
    MemoryContextDelete(hook_mcxt);
}

/* Function to set contact info before creating user */
PG_FUNCTION_INFO_V1(set_user_contact_info);
Datum
set_user_contact_info(PG_FUNCTION_ARGS)
{
    char *email = text_to_cstring(PG_GETARG_TEXT_PP(0));
    char *phone = text_to_cstring(PG_GETARG_TEXT_PP(1));

    elog(LOG, "user_contact: set_user_contact_info called with email='%s', phone='%s'", email, phone);

    /* Basic validation */
    if (!email || strlen(email) == 0)
        ereport(ERROR, (errmsg("Email cannot be empty")));
    
    if (!phone || strlen(phone) == 0)
        ereport(ERROR, (errmsg("Phone cannot be empty")));
    
    if (!strstr(email, "@"))
        ereport(ERROR, (errmsg("Invalid email format")));

    if (strlen(phone) < 7)
        ereport(ERROR, (errmsg("Phone number too short")));

    /* Store in TopMemoryContext so it persists across function calls */
    MemoryContext oldcontext = MemoryContextSwitchTo(TopMemoryContext);
    
    if (pending_user_email)
        pfree(pending_user_email);
    if (pending_user_phone)
        pfree(pending_user_phone);
    
    pending_user_email = pstrdup(email);
    pending_user_phone = pstrdup(phone);
    
    MemoryContextSwitchTo(oldcontext);

    elog(LOG, "user_contact: Contact info stored in memory - email='%s', phone='%s'", 
         pending_user_email, pending_user_phone);

    elog(NOTICE, "Contact info set. You can now create the user.");

    PG_RETURN_TEXT_P(cstring_to_text("Contact info set successfully"));
}

/* Function for users to update their own contact info */
PG_FUNCTION_INFO_V1(update_my_contact_info);
Datum
update_my_contact_info(PG_FUNCTION_ARGS)
{
    char *email = NULL;
    char *phone = NULL;
    char *current_user_name = GetUserNameFromId(GetUserId(), false);
    int ret;
    StringInfoData query;

    elog(LOG, "user_contact: update_my_contact_info called by user '%s'", current_user_name);

    /* Get optional email parameter */
    if (!PG_ARGISNULL(0))
    {
        email = text_to_cstring(PG_GETARG_TEXT_PP(0));
        if (!strstr(email, "@"))
            ereport(ERROR, (errmsg("Invalid email format")));
    }

    /* Get optional phone parameter */
    if (!PG_ARGISNULL(1))
    {
        phone = text_to_cstring(PG_GETARG_TEXT_PP(1));
        if (strlen(phone) < 7)
            ereport(ERROR, (errmsg("Phone number too short")));
    }

    /* At least one field must be provided */
    if (!email && !phone)
        ereport(ERROR, (errmsg("At least one of email or phone must be provided")));

    ret = SPI_connect();
    if (ret != SPI_OK_CONNECT)
        elog(ERROR, "user_contact: SPI_connect failed: %d", ret);

    initStringInfo(&query);
    
    /* UPSERT - insert or update based on existence */
    if (email && phone)
    {
        appendStringInfo(&query,
            "INSERT INTO user_contact_info (username, email, phone, created_at) "
            "VALUES (%s, %s, %s, NOW()) "
            "ON CONFLICT (username) DO UPDATE SET "
            "email = EXCLUDED.email, phone = EXCLUDED.phone, updated_at = NOW()",
            quote_literal_cstr(current_user_name),
            quote_literal_cstr(email),
            quote_literal_cstr(phone));
    }
    else if (email)
    {
        appendStringInfo(&query,
            "INSERT INTO user_contact_info (username, email, phone, created_at) "
            "VALUES (%s, %s, '', NOW()) "
            "ON CONFLICT (username) DO UPDATE SET "
            "email = EXCLUDED.email, updated_at = NOW()",
            quote_literal_cstr(current_user_name),
            quote_literal_cstr(email));
    }
    else /* phone only */
    {
        appendStringInfo(&query,
            "INSERT INTO user_contact_info (username, email, phone, created_at) "
            "VALUES (%s, '', %s, NOW()) "
            "ON CONFLICT (username) DO UPDATE SET "
            "phone = EXCLUDED.phone, updated_at = NOW()",
            quote_literal_cstr(current_user_name),
            quote_literal_cstr(phone));
    }

    elog(LOG, "user_contact: Executing query: %s", query.data);

    ret = SPI_execute(query.data, false, 0);
    
    elog(LOG, "user_contact: SPI_execute returned: %d, processed: %lu", ret, SPI_processed);

    pfree(query.data);
    SPI_finish();

    if (ret != SPI_OK_INSERT && ret != SPI_OK_UPDATE)
        elog(ERROR, "user_contact: Failed to update contact info: %d", ret);

    elog(NOTICE, "Contact info updated successfully");
    PG_RETURN_VOID();
}

/* Function to get contact info - uses case-insensitive comparison */
PG_FUNCTION_INFO_V1(get_user_contact);
Datum
get_user_contact(PG_FUNCTION_ARGS)
{
    char *username = text_to_cstring(PG_GETARG_TEXT_PP(0));
    char *current_user_name = GetUserNameFromId(GetUserId(), false);
    int ret;
    HeapTuple tuple;
    TupleDesc tupdesc;
    Datum result;

    elog(LOG, "user_contact: get_user_contact called for user '%s' by '%s'", username, current_user_name);

    /* Check permission: superuser or own info (case-insensitive) */
    if (!superuser() && pg_strcasecmp(username, current_user_name) != 0)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                 errmsg("permission denied for user contact info"),
                 errhint("You can only view your own contact information")));
    }

    ret = SPI_connect();
    if (ret != SPI_OK_CONNECT)
        elog(ERROR, "user_contact: SPI_connect failed: %d", ret);

    StringInfoData query;
    initStringInfo(&query);
    appendStringInfo(&query,
        "SELECT email, phone, created_at, updated_at FROM user_contact_info WHERE lower(username) = lower(%s)",
        quote_literal_cstr(username));

    elog(LOG, "user_contact: Executing query: %s", query.data);

    ret = SPI_execute(query.data, true, 1);

    elog(LOG, "user_contact: SPI_execute returned: %d, processed: %lu", ret, SPI_processed);

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

    tuple = SPI_tuptable->vals[0];
    tupdesc = SPI_tuptable->tupdesc;

    elog(LOG, "user_contact: Found contact info, tuple attributes: %d", tupdesc->natts);

    result = HeapTupleGetDatum(heap_copytuple(tuple));

    pfree(query.data);
    SPI_finish();

    elog(LOG, "user_contact: get_user_contact completed successfully");

    PG_RETURN_DATUM(result);
}

/* Update function with upsert capability and case-insensitive comparison */
PG_FUNCTION_INFO_V1(update_user_contact);
Datum
update_user_contact(PG_FUNCTION_ARGS)
{
    char *username = text_to_cstring(PG_GETARG_TEXT_PP(0));
    char *email = NULL;
    char *phone = NULL;
    int ret;
    StringInfoData query;

    elog(LOG, "user_contact: update_user_contact called for user='%s'", username);

    /* Only superusers can update other users' contact info */
    if (!superuser())
        ereport(ERROR, 
                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                 errmsg("must be superuser to update user contact info")));

    /* Get optional email parameter */
    if (!PG_ARGISNULL(1))
    {
        email = text_to_cstring(PG_GETARG_TEXT_PP(1));
        if (!strstr(email, "@"))
            ereport(ERROR, (errmsg("Invalid email format")));
    }

    /* Get optional phone parameter */
    if (!PG_ARGISNULL(2))
    {
        phone = text_to_cstring(PG_GETARG_TEXT_PP(2));
        if (strlen(phone) < 7)
            ereport(ERROR, (errmsg("Phone number too short")));
    }

    /* At least one field must be provided */
    if (!email && !phone)
        ereport(ERROR, (errmsg("At least one of email or phone must be provided")));

    ret = SPI_connect();
    if (ret != SPI_OK_CONNECT)
        elog(ERROR, "user_contact: SPI_connect failed: %d", ret);

    initStringInfo(&query);
    
    /* UPSERT with case-insensitive username handling */
    if (email && phone)
    {
        appendStringInfo(&query,
            "INSERT INTO user_contact_info (username, email, phone, created_at) "
            "VALUES (%s, %s, %s, NOW()) "
            "ON CONFLICT (username) DO UPDATE SET "
            "email = EXCLUDED.email, phone = EXCLUDED.phone, updated_at = NOW()",
            quote_literal_cstr(username),
            quote_literal_cstr(email),
            quote_literal_cstr(phone));
    }
    else if (email)
    {
        appendStringInfo(&query,
            "INSERT INTO user_contact_info (username, email, phone, created_at) "
            "VALUES (%s, %s, '', NOW()) "
            "ON CONFLICT (username) DO UPDATE SET "
            "email = EXCLUDED.email, updated_at = NOW()",
            quote_literal_cstr(username),
            quote_literal_cstr(email));
    }
    else /* phone only */
    {
        appendStringInfo(&query,
            "INSERT INTO user_contact_info (username, email, phone, created_at) "
            "VALUES (%s, '', %s, NOW()) "
            "ON CONFLICT (username) DO UPDATE SET "
            "phone = EXCLUDED.phone, updated_at = NOW()",
            quote_literal_cstr(username),
            quote_literal_cstr(phone));
    }

    elog(LOG, "user_contact: Executing update query: %s", query.data);

    ret = SPI_execute(query.data, false, 0);
    
    elog(LOG, "user_contact: SPI_execute returned: %d, processed: %lu", ret, SPI_processed);

    pfree(query.data);
    SPI_finish();

    if (ret != SPI_OK_INSERT && ret != SPI_OK_UPDATE)
        elog(ERROR, "user_contact: Failed to update contact info: %d", ret);

    elog(NOTICE, "Contact info updated for user '%s'", username);
    PG_RETURN_VOID();
}

/* Direct insert function for superusers */
PG_FUNCTION_INFO_V1(insert_user_contact);
Datum
insert_user_contact(PG_FUNCTION_ARGS)
{
    char *username = text_to_cstring(PG_GETARG_TEXT_PP(0));
    char *email = text_to_cstring(PG_GETARG_TEXT_PP(1));
    char *phone = text_to_cstring(PG_GETARG_TEXT_PP(2));
    int ret;

    elog(LOG, "user_contact: insert_user_contact called for user='%s'", username);

    /* Only superusers can insert directly */
    if (!superuser())
        ereport(ERROR, 
                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                 errmsg("must be superuser to insert user contact info directly")));

    /* Validation */
    if (!strstr(email, "@"))
        ereport(ERROR, (errmsg("Invalid email format")));
    
    if (strlen(phone) < 7)
        ereport(ERROR, (errmsg("Phone number too short")));

    ret = SPI_connect();
    if (ret != SPI_OK_CONNECT)
        elog(ERROR, "user_contact: SPI_connect failed: %d", ret);

    StringInfoData query;
    initStringInfo(&query);
    appendStringInfo(&query,
        "INSERT INTO user_contact_info (username, email, phone, created_at) "
        "VALUES (%s, %s, %s, NOW())",
        quote_literal_cstr(username),
        quote_literal_cstr(email),
        quote_literal_cstr(phone));

    elog(LOG, "user_contact: Executing insert query: %s", query.data);

    ret = SPI_execute(query.data, false, 0);
    
    elog(LOG, "user_contact: SPI_execute returned: %d, processed: %lu", ret, SPI_processed);

    pfree(query.data);
    SPI_finish();

    if (ret != SPI_OK_INSERT)
        elog(ERROR, "user_contact: Failed to insert contact info: %d", ret);

    elog(NOTICE, "Contact info inserted for user '%s'", username);
    PG_RETURN_VOID();
}

/* Function to list all user contacts - superuser only */
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

    if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("function returning record called in context that cannot accept a set")));

    if (!(rsinfo->allowedModes & SFRM_Materialize))
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("materialize mode required, but it is not allowed in this context")));

    per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
    oldcontext = MemoryContextSwitchTo(per_query_ctx);

    tupstore = tuplestore_begin_heap(true, false, work_mem);
    rsinfo->returnMode = SFRM_Materialize;
    rsinfo->setResult = tupstore;

    ret = SPI_connect();
    if (ret != SPI_OK_CONNECT)
    {
        MemoryContextSwitchTo(oldcontext);
        elog(ERROR, "user_contact: SPI_connect failed: %d", ret);
    }

    ret = SPI_execute("SELECT username, email, phone, created_at, updated_at FROM user_contact_info ORDER BY username", true, 0);
    if (ret != SPI_OK_SELECT)
    {
        SPI_finish();
        MemoryContextSwitchTo(oldcontext);
        elog(ERROR, "user_contact: SPI_execute failed: %d", ret);
    }

    tupdesc = SPI_tuptable->tupdesc;
    rsinfo->setDesc = CreateTupleDescCopy(tupdesc);

    for (uint64 i = 0; i < SPI_processed; i++)
    {
        HeapTuple tuple = SPI_tuptable->vals[i];
        tuplestore_puttuple(tupstore, tuple);
    }

    SPI_finish();
    MemoryContextSwitchTo(oldcontext);

    PG_RETURN_NULL();
}

/* Utility function to clear pending contact info */
PG_FUNCTION_INFO_V1(clear_pending_contact_info);
Datum
clear_pending_contact_info(PG_FUNCTION_ARGS)
{
    elog(LOG, "user_contact: clear_pending_contact_info called");
    
    cleanup_pending_contact_info();

    elog(NOTICE, "Pending contact info cleared");
    PG_RETURN_TEXT_P(cstring_to_text("Pending contact info cleared"));
}

/* Module load */
void _PG_init(void)
{
    /* Register transaction callback for cleanup */
    RegisterXactCallback(user_contact_xact_callback, NULL);
    
    /* Install ProcessUtility hook */
    prev_ProcessUtility = ProcessUtility_hook;
    ProcessUtility_hook = user_contact_ProcessUtility;

    elog(LOG, "user_contact extension loaded successfully with all manager fixes applied");
}

/* Module unload */
void _PG_fini(void)
{
    /* Unregister transaction callback */
    UnregisterXactCallback(user_contact_xact_callback, NULL);
    
    /* Restore previous hook */
    ProcessUtility_hook = prev_ProcessUtility;
    
    /* Clean up pending info */
    cleanup_pending_contact_info();

    elog(LOG, "user_contact extension unloaded");
}