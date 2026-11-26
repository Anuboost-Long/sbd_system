/* Evidence queries for the report (run as sa; synthetic demo data only).
   Sign in through the front end first, so the Sessions table has rows. */

-- 1. Passwords are stored as salted PBKDF2 hashes, never plain text (A1, A2)
USE AuthDb;
GO
SELECT UserName,
       LEFT(PasswordHash, 40) + '...' AS PasswordHashStart,
       LEN(PasswordHash)              AS HashLength
FROM dbo.AspNetUsers
ORDER BY UserName;
GO

-- 2. Session tokens are stored only as a 32-byte SHA-256 hash (A9)
SELECT TOP 5 SessionId, UserId,
       CONVERT(VARCHAR(66), TokenHash, 1) AS TokenHashHex,
       DATALENGTH(TokenHash)              AS HashBytes,
       CreatedUtc, AbsoluteExpiryUtc, RevokedUtc
FROM dbo.Sessions
ORDER BY SessionId DESC;
GO

-- 3. Medical status, card number and expiry are encrypted: v1: + Base64 (E1)
USE CustomerDb;
GO
SELECT TOP 5 CustomerId, LastName, CardLast4,
       MedicalStatusEnc, LEN(MedicalStatusEnc) AS MedicalLen,
       LEFT(CardNumberEnc, 30) + '...'         AS CardNumberEncStart, LEN(CardNumberEnc) AS CardLen,
       LEFT(CardExpiryEnc, 30) + '...'         AS CardExpiryEncStart, LEN(CardExpiryEnc) AS ExpiryLen
FROM dbo.Customers
ORDER BY CustomerId;
GO

-- 4. Audit trail of the demo: who did what, with the approval reference (R6, R8)
USE AuthDb;
GO
SELECT TOP 30 AuditId, OccurredUtc, Action, Outcome, ActorUserId, TargetUserId, TargetCustomerId, ApprovalRef, ClientIp
FROM dbo.AuditLog
ORDER BY AuditId DESC;
GO

-- 5. Security alerts raised (lockout, role assigned, limits)
SELECT TOP 20 AlertId, RaisedUtc, UserId, AlertType, ResolvedByUserId, ResolvedUtc
FROM dbo.SecurityAlerts
ORDER BY AlertId DESC;
GO
