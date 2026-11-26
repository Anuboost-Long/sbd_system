/* =============================================================================
   02_customer_views.sql  (CustomerDb)
   Run as: deployment account.

   [Guide 4.3] Role-based access enforced INSIDE the database: one view per
   data role, exposing only the columns that role may see (access matrix 4.1).
   The API also filters fields per role; these views are the second,
   independent layer, so a coding mistake in the API cannot reach columns the
   role is not allowed to see.
   Standard: OWASP ASVS 5.0 V8.2.3 (field-level access); Sandhu et al. (1996).

   SCHEMABINDING stops anyone changing the underlying table in a way that would
   silently alter what a view exposes.
   ============================================================================= */
USE CustomerDb;
GO

-- Normal: name, address, phone only (no card, no medical)
CREATE OR ALTER VIEW dbo.vw_Normal
WITH SCHEMABINDING
AS
SELECT  c.CustomerId,
        c.FirstName, c.LastName,
        c.Unit, c.Street, l.Suburb, l.State, l.Postcode,
        c.Phone
FROM    dbo.Customers  AS c
JOIN    dbo.Localities AS l ON l.LocalityId = c.LocalityId;
GO

-- Accounting: Normal fields + card data (masked by default; full number only
-- through the logged reveal action). No medical status.
CREATE OR ALTER VIEW dbo.vw_Accounting
WITH SCHEMABINDING
AS
SELECT  c.CustomerId,
        c.FirstName, c.LastName,
        c.Unit, c.Street, l.Suburb, l.State, l.Postcode,
        c.Phone,
        c.CardLast4, c.CardNumberEnc, c.CardExpiryEnc
FROM    dbo.Customers  AS c
JOIN    dbo.Localities AS l ON l.LocalityId = c.LocalityId;
GO

-- Privileged: all fields, including medical status
CREATE OR ALTER VIEW dbo.vw_Privileged
WITH SCHEMABINDING
AS
SELECT  c.CustomerId,
        c.FirstName, c.LastName,
        c.Unit, c.Street, l.Suburb, l.State, l.Postcode,
        c.Phone,
        c.CardLast4, c.CardNumberEnc, c.CardExpiryEnc,
        c.MedicalStatusEnc
FROM    dbo.Customers  AS c
JOIN    dbo.Localities AS l ON l.LocalityId = c.LocalityId;
GO
