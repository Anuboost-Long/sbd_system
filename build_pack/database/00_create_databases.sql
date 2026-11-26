/* =============================================================================
   00_create_databases.sql
   Run as: deployment account (sa in local development only).

   [Guide 3.2] Customer data and login data live in two separate databases, so a
   flaw in the search path can never reach password hashes or session tokens.
   Standard: ISO/IEC 27001:2022 (segregation), OWASP ASVS 5.0 V8 (least privilege).
   ============================================================================= */

IF DB_ID(N'CustomerDb') IS NULL
    CREATE DATABASE CustomerDb;
GO

IF DB_ID(N'AuthDb') IS NULL
    CREATE DATABASE AuthDb;
GO
