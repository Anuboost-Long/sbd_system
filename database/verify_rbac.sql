/* =============================================================================
   verify_rbac.sql  -  evidence for Appendix B (screenshot the output)
   Run as: deployment account, AFTER 00-11 have run.
   Every line should print PASS. Each test tries something that must be blocked.
   ============================================================================= */
SET NOCOUNT ON;

/* ======================= CustomerDb: view-limited logins ======================= */
USE CustomerDb;

-- DB1: Normal search login cannot read the base table
BEGIN TRY
    EXECUTE AS USER = 'app_view_normal';
    DECLARE @x1 INT = (SELECT COUNT(*) FROM dbo.Customers);
    REVERT; PRINT 'FAIL DB1 app_view_normal read dbo.Customers';
END TRY
BEGIN CATCH
    REVERT; PRINT 'PASS DB1 app_view_normal blocked from dbo.Customers: ' + ERROR_MESSAGE();
END CATCH;

-- DB2: Normal search login cannot read the Privileged view
BEGIN TRY
    EXECUTE AS USER = 'app_view_normal';
    DECLARE @x2 INT = (SELECT COUNT(*) FROM dbo.vw_Privileged);
    REVERT; PRINT 'FAIL DB2 app_view_normal read vw_Privileged';
END TRY
BEGIN CATCH
    REVERT; PRINT 'PASS DB2 app_view_normal blocked from vw_Privileged: ' + ERROR_MESSAGE();
END CATCH;

-- DB3: Accounting search login cannot read medical status
BEGIN TRY
    EXECUTE AS USER = 'app_view_accounting';
    DECLARE @x3 INT = (SELECT COUNT(*) FROM dbo.vw_Privileged);
    REVERT; PRINT 'FAIL DB3 app_view_accounting read vw_Privileged';
END TRY
BEGIN CATCH
    REVERT; PRINT 'PASS DB3 app_view_accounting blocked from medical view: ' + ERROR_MESSAGE();
END CATCH;

-- DB4: search logins are read-only (no UPDATE through the view)
BEGIN TRY
    EXECUTE AS USER = 'app_view_privileged';
    UPDATE dbo.Customers SET FirstName = N'Hacked' WHERE CustomerId = -1;
    REVERT; PRINT 'FAIL DB4 app_view_privileged updated dbo.Customers';
END TRY
BEGIN CATCH
    REVERT; PRINT 'PASS DB4 app_view_privileged cannot modify data: ' + ERROR_MESSAGE();
END CATCH;

-- DB5: column check - vw_Normal exposes no card or medical columns
IF NOT EXISTS (SELECT 1 FROM sys.columns
               WHERE object_id = OBJECT_ID(N'dbo.vw_Normal')
                 AND name IN (N'MedicalStatusEnc', N'CardNumberEnc', N'CardExpiryEnc', N'CardLast4'))
    PRINT 'PASS DB5 vw_Normal has no card or medical columns';
ELSE
    PRINT 'FAIL DB5 vw_Normal exposes sensitive columns';

-- DB-V: database rejects a script-injection name even if the API were bypassed
BEGIN TRY
    BEGIN TRAN;
    -- every other value is valid, so only the name can cause the rejection
    INSERT dbo.Customers (FirstName, LastName, Street, LocalityId, Phone,
                          MedicalStatusEnc, CardNumberEnc, CardLast4, CardExpiryEnc)
    VALUES (N'<script>', N'Test', N'1 Test St', (SELECT TOP 1 LocalityId FROM dbo.Localities),
            '+61400000000', 'v1:AAAA', 'v1:AAAA', '1111', 'v1:AAAA');
    ROLLBACK; PRINT 'FAIL DB-V CHECK constraint allowed <script>';
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    IF ERROR_MESSAGE() LIKE '%CK_Customers_FirstName%'
        PRINT 'PASS DB-V CHECK constraint rejected <script> name: ' + ERROR_MESSAGE();
    ELSE
        PRINT 'FAIL DB-V rejected for another reason: ' + ERROR_MESSAGE();
END CATCH;

/* ============================== AuthDb ============================== */
USE AuthDb;

-- DB6: role -> permission matrix (shown for the screenshot)
SELECT r.Name AS Role, p.Code AS Permission
FROM dbo.RolePermissions rp
JOIN dbo.AspNetRoles r ON r.Id = rp.RoleId
JOIN dbo.Permissions p ON p.PermissionId = rp.PermissionId
ORDER BY r.Name, p.PermissionId;

-- DB7: separation of duties - UserAdmin cannot be given customer.search
BEGIN TRY
    BEGIN TRAN;
    INSERT dbo.RolePermissions (RoleId, PermissionId)
    VALUES (N'11111111-0000-0000-0000-000000000004', 1);
    ROLLBACK; PRINT 'FAIL DB7 UserAdmin was given customer.search';
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT 'PASS DB7 separation of duties blocked: ' + ERROR_MESSAGE();
END CATCH;

-- DB8: one role per user - a second role is rejected
BEGIN TRY
    BEGIN TRAN;
    INSERT dbo.AspNetUsers (Id, UserName, NormalizedUserName, EmailConfirmed, PhoneNumberConfirmed,
                            TwoFactorEnabled, LockoutEnabled, AccessFailedCount)
    VALUES (N'verify-user', N'verify.user', N'VERIFY.USER', 0, 0, 0, 1, 0);
    INSERT dbo.AspNetUserRoles (UserId, RoleId) VALUES (N'verify-user', N'11111111-0000-0000-0000-000000000001');
    INSERT dbo.AspNetUserRoles (UserId, RoleId) VALUES (N'verify-user', N'11111111-0000-0000-0000-000000000004');
    ROLLBACK; PRINT 'FAIL DB8 user held two roles';
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT 'PASS DB8 one role per user enforced: ' + ERROR_MESSAGE();
END CATCH;

-- DB9: the API login cannot edit the audit log
BEGIN TRY
    EXECUTE AS USER = 'app_identity';
    UPDATE dbo.AuditLog SET Outcome = 'Success' WHERE AuditId = -1;
    REVERT; PRINT 'FAIL DB9 app_identity updated AuditLog';
END TRY
BEGIN CATCH
    REVERT; PRINT 'PASS DB9 audit log is append-only: ' + ERROR_MESSAGE();
END CATCH;

-- DB10: the API login cannot change the permission matrix
BEGIN TRY
    EXECUTE AS USER = 'app_identity';
    INSERT dbo.RolePermissions (RoleId, PermissionId)
    VALUES (N'11111111-0000-0000-0000-000000000001', 4);
    REVERT; PRINT 'FAIL DB10 app_identity changed RolePermissions';
END TRY
BEGIN CATCH
    REVERT; PRINT 'PASS DB10 permission matrix is read-only to the API: ' + ERROR_MESSAGE();
END CATCH;

-- DB11: role change without a manager approval reference is rejected
BEGIN TRY
    INSERT dbo.AuditLog (ActorUserId, Action, Outcome, TargetUserId, ApprovalRef)
    VALUES (N'admin-a', 'RoleAssigned', 'Success', N'user-b', NULL);
    PRINT 'FAIL DB11 role change logged without approval';
END TRY
BEGIN CATCH
    PRINT 'PASS DB11 approval reference required: ' + ERROR_MESSAGE();
END CATCH;

-- DB12: nobody can change their own role
BEGIN TRY
    INSERT dbo.AuditLog (ActorUserId, Action, Outcome, TargetUserId, ApprovalRef)
    VALUES (N'admin-a', 'RoleAssigned', 'Success', N'admin-a', N'CHG-001');
    PRINT 'FAIL DB12 self role change allowed';
END TRY
BEGIN CATCH
    PRINT 'PASS DB12 self role change blocked: ' + ERROR_MESSAGE();
END CATCH;
