/*
 * user_contact.c - COMPLETELY FIXED VERSION
 * PostgreSQL extension for storing user contact info with proper debugging
 */

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
 
 PG_MODULE_MAGIC;
 
 /* Previous hook */
 static ProcessUtility_hook_type prev_ProcessUtility = NULL;
 
 /* Session memory for pending contact info */
 static char *pending_user_email = NULL;
 static char *pending_user_phone = NULL;
 
 /* Hook function with enhanced logging */
 static void user_contact_ProcessUtility(PlannedStmt *pstmt,
                                         const char *queryString,
                                         bool readOnlyTree,
                                         ProcessUtilityContext context,
                                         ParamListInfo params,
                                         QueryEnvironment *queryEnv,
                                         DestReceiver *dest,
                                         QueryCompletion *qc)
 {
     Node *parsetree = pstmt->utilityStmt;
 
     /* Intercept CREATE USER / CREATE ROLE before execution */
     if (IsA(parsetree, CreateRoleStmt))
     {
         CreateRoleStmt *stmt = (CreateRoleStmt *) parsetree;
         bool is_user = false;
 
         elog(LOG, "user_contact: Intercepted CREATE ROLE/USER for '%s'", stmt->role);
 
         /* Determine if it's a login role */
         ListCell *option;
         foreach(option, stmt->options)
         {
             DefElem *defel = (DefElem *) lfirst(option);
             if (strcmp(defel->defname, "login") == 0)
             {
                 if (defel->arg && IsA(defel->arg, Boolean))
                     is_user = DatumGetBool(((Const *)defel->arg)->constvalue);
                 break;
             }
         }
 
         if (!is_user && stmt->stmt_type == ROLESTMT_USER)
             is_user = true;
 
         elog(LOG, "user_contact: is_user = %s", is_user ? "true" : "false");
 
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
                          errhint("Use: SELECT set_user_contact_info('email@example.com', '1234567890'); before CREATE USER")));
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
 
     /* Call original ProcessUtility to execute the command */
     if (prev_ProcessUtility)
         prev_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
     else
         standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
 
     /* After successful CREATE USER, insert contact info */
     if (IsA(parsetree, CreateRoleStmt))
     {
         CreateRoleStmt *stmt = (CreateRoleStmt *) parsetree;
         bool is_user = false;
 
         ListCell *option;
         foreach(option, stmt->options)
         {
             DefElem *defel = (DefElem *) lfirst(option);
             if (strcmp(defel->defname, "login") == 0)
             {
                 if (defel->arg && IsA(defel->arg, Boolean))
                     is_user = DatumGetBool(((Const *)defel->arg)->constvalue);
                 break;
             }
         }
 
         if (!is_user && stmt->stmt_type == ROLESTMT_USER)
             is_user = true;
 
         if (is_user && pending_user_email && pending_user_phone)
         {
             int ret;
             
             elog(LOG, "user_contact: Attempting to store contact info for user '%s'", stmt->role);
             
             ret = SPI_connect();
             if (ret != SPI_OK_CONNECT)
             {
                 elog(ERROR, "user_contact: SPI_connect failed: %d", ret);
                 return;
             }
 
             /* Simple INSERT using SPI_execute - more reliable than parameterized version */
             StringInfoData query;
             initStringInfo(&query);
             
             /* Use quote_literal_cstr to prevent SQL injection */
             appendStringInfo(&query,
                 "INSERT INTO user_contact_info(username, email, phone, created_at) "
                 "VALUES (%s, %s, %s, NOW()) "
                 "ON CONFLICT (username) DO UPDATE SET "
                 "email = EXCLUDED.email, phone = EXCLUDED.phone, updated_at = NOW()",
                 quote_literal_cstr(stmt->role),
                 quote_literal_cstr(pending_user_email),
                 quote_literal_cstr(pending_user_phone));
 
             elog(LOG, "user_contact: Executing query: %s", query.data);
 
             ret = SPI_execute(query.data, false, 0);
             
             elog(LOG, "user_contact: SPI_execute returned: %d, processed: %lu", ret, SPI_processed);
             
             if (ret != SPI_OK_INSERT && ret != SPI_OK_UPDATE)
                 elog(WARNING, "user_contact: Failed to insert contact info for user '%s': %d", stmt->role, ret);
             else
                 elog(NOTICE, "Contact info stored for user '%s'", stmt->role);
 
             pfree(query.data);
             SPI_finish();
 
             /* Clear the pending contact info */
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
             
             elog(LOG, "user_contact: Contact info insertion completed");
         }
     }
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
 
 /* COMPLETELY REWRITTEN: Simple function to get contact info */
 PG_FUNCTION_INFO_V1(get_user_contact);
 Datum
 get_user_contact(PG_FUNCTION_ARGS)
 {
     char *username = text_to_cstring(PG_GETARG_TEXT_PP(0));
     int ret;
     HeapTuple tuple;
     TupleDesc tupdesc;
     Datum result;
 
     elog(LOG, "user_contact: get_user_contact called for user '%s'", username);
 
     ret = SPI_connect();
     if (ret != SPI_OK_CONNECT)
     {
         elog(ERROR, "user_contact: SPI_connect failed: %d", ret);
         PG_RETURN_NULL();
     }
 
     /* Use simple SPI_execute with quoted string */
     StringInfoData query;
     initStringInfo(&query);
     appendStringInfo(&query,
         "SELECT email, phone, created_at, updated_at FROM user_contact_info WHERE username = %s",
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
 
     /* Get the result tuple */
     tuple = SPI_tuptable->vals[0];
     tupdesc = SPI_tuptable->tupdesc;
 
     elog(LOG, "user_contact: Found contact info, tuple attributes: %d", tupdesc->natts);
 
     /* Create a copy of the tuple in the upper context */
     result = HeapTupleGetDatum(heap_copytuple(tuple));
 
     pfree(query.data);
     SPI_finish();
 
     elog(LOG, "user_contact: get_user_contact completed successfully");
 
     PG_RETURN_DATUM(result);
 }
 
 /* FIXED: Update function with detailed logging */
 PG_FUNCTION_INFO_V1(update_user_contact);
 Datum
 update_user_contact(PG_FUNCTION_ARGS)
 {
     char *username = text_to_cstring(PG_GETARG_TEXT_PP(0));
     char *email    = text_to_cstring(PG_GETARG_TEXT_PP(1));
     char *phone    = text_to_cstring(PG_GETARG_TEXT_PP(2));
     int ret;
 
     elog(LOG, "user_contact: update_user_contact called for user='%s', email='%s', phone='%s'", 
          username, email, phone);
 
     /* Only superusers can update contact info */
     if (!superuser())
         ereport(ERROR, 
                 (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                  errmsg("must be superuser to update user contact info")));
 
     /* Basic validation */
     if (!strstr(email, "@"))
         ereport(ERROR, (errmsg("Invalid email format")));
     
     if (strlen(phone) < 7)
         ereport(ERROR, (errmsg("Phone number too short")));
 
     ret = SPI_connect();
     if (ret != SPI_OK_CONNECT)
     {
         elog(ERROR, "user_contact: SPI_connect failed: %d", ret);
         PG_RETURN_VOID();
     }
 
     /* Use simple SPI_execute with proper quoting */
     StringInfoData query;
     initStringInfo(&query);
     appendStringInfo(&query,
         "UPDATE user_contact_info SET email = %s, phone = %s, updated_at = NOW() WHERE username = %s",
         quote_literal_cstr(email),
         quote_literal_cstr(phone),
         quote_literal_cstr(username));
 
     elog(LOG, "user_contact: Executing update query: %s", query.data);
 
     ret = SPI_execute(query.data, false, 0);
     
     elog(LOG, "user_contact: SPI_execute returned: %d, processed: %lu", ret, SPI_processed);
 
     if (ret != SPI_OK_UPDATE)
     {
         pfree(query.data);
         SPI_finish();
         elog(ERROR, "user_contact: Failed to update contact info: %d", ret);
     }
 
     if (SPI_processed == 0)
     {
         pfree(query.data);
         SPI_finish();
         ereport(ERROR, (errmsg("User not found: %s", username)));
     }
 
     pfree(query.data);
     SPI_finish();
 
     elog(NOTICE, "Contact info updated for user '%s'", username);
     PG_RETURN_VOID();
 }
 
 /* Function to list all user contacts */
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
 
     elog(NOTICE, "Pending contact info cleared");
     PG_RETURN_TEXT_P(cstring_to_text("Pending contact info cleared"));
 }

 /* Module load */
 void _PG_init(void)
 {
     /* Install the ProcessUtility hook */
     prev_ProcessUtility = ProcessUtility_hook;
     ProcessUtility_hook = user_contact_ProcessUtility;
 
     elog(LOG, "user_contact extension loaded successfully with debugging enabled");
 }
 
 /* Module unload */
 void _PG_fini(void)
 {
     /* Restore the previous hook */
     ProcessUtility_hook = prev_ProcessUtility;
     
     /* Clean up memory */
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
 
     elog(LOG, "user_contact extension unloaded");
 }