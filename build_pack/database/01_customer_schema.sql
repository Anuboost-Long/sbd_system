/* =============================================================================
   01_customer_schema.sql  (CustomerDb)
   Run as: deployment account.

   [Guide 3.1] Every stored field repeats the Section 2.1 input limit, so the
   database is a second barrier if application validation is ever bypassed
   (defence in depth). The API's server-side allowlist is the primary control;
   the CHECK constraints below are a backstop that rejects obviously unsafe
   characters and wrong formats.
   ============================================================================= */
USE CustomerDb;
GO

/* ---------------------------------------------------------------------------
   Localities: single source of truth for valid state/suburb/postcode
   combinations (Guide 2.1, 3.1). Feeds the dropdowns, the API check and the
   foreign key below, so UI, server and storage always agree.
   --------------------------------------------------------------------------- */
IF OBJECT_ID(N'dbo.Localities', N'U') IS NULL
CREATE TABLE dbo.Localities (
    LocalityId  INT IDENTITY(1,1) NOT NULL
        CONSTRAINT PK_Localities PRIMARY KEY,

    -- 46 chars: WA address standard locality-name limit (DPC WA, 2022)
    Suburb      NVARCHAR(46) NOT NULL
        CONSTRAINT CK_Localities_Suburb
        CHECK (LEN(TRIM(Suburb)) > 0 AND Suburb NOT LIKE N'%[^a-zA-Z ''-]%'),

    -- 3 chars: longest Australian state code (NSW, VIC ...). VARCHAR avoids padding.
    State       VARCHAR(3) NOT NULL
        CONSTRAINT CK_Localities_State
        CHECK (State IN ('NSW','VIC','QLD','SA','WA','TAS','NT','ACT')),

    -- Exactly 4 digits, stored as text so leading zeros survive (e.g. 0800 Darwin)
    Postcode    CHAR(4) NOT NULL
        CONSTRAINT CK_Localities_Postcode
        CHECK (Postcode LIKE '[0-9][0-9][0-9][0-9]'),

    CONSTRAINT UQ_Localities_Combination UNIQUE (Suburb, State, Postcode)
);
GO

/* ---------------------------------------------------------------------------
   Customers: the data subjects (they never log in).
   Sensitive fields are stored ONLY as AES-256-GCM ciphertext produced by the
   API (Guide 3.3). The database never sees the plaintext or the key, so
   database staff and stolen backups only expose scrambled values.
   Stored format: "v1:" + Base64(12-byte nonce | ciphertext | 16-byte tag).
   --------------------------------------------------------------------------- */
IF OBJECT_ID(N'dbo.Customers', N'U') IS NULL
CREATE TABLE dbo.Customers (
    CustomerId      INT IDENTITY(1,1) NOT NULL
        CONSTRAINT PK_Customers PRIMARY KEY,

    -- 50 chars: above the 40-char AIHW name standard, below WA advice of 80.
    -- Unicode (N) so accented names such as Zoë are stored correctly.
    FirstName       NVARCHAR(50) NOT NULL
        CONSTRAINT CK_Customers_FirstName
        CHECK (LEN(TRIM(FirstName)) > 0
               AND FirstName NOT LIKE N'%[0-9<>;=@#$%_*?!"/\|{}()+&]%'),

    LastName        NVARCHAR(50) NOT NULL
        CONSTRAINT CK_Customers_LastName
        CHECK (LEN(TRIM(LastName)) > 0
               AND LastName NOT LIKE N'%[0-9<>;=@#$%_*?!"/\|{}()+&]%'),

    -- 10 chars: WA 7-char sub-dwelling number plus prefix; NULL for houses
    Unit            NVARCHAR(10) NULL
        CONSTRAINT CK_Customers_Unit
        CHECK (Unit IS NULL OR (LEN(TRIM(Unit)) > 0 AND Unit NOT LIKE N'%[^a-zA-Z0-9/-]%')),

    -- 60 chars: WA road number (6) + road name (45) + road type (4) + spaces
    Street          NVARCHAR(60) NOT NULL
        CONSTRAINT CK_Customers_Street
        CHECK (LEN(TRIM(Street)) > 0
               AND Street NOT LIKE N'%[<>;=@#$%_*?!"\|{}()+&]%'),

    -- Must point to an existing valid combination (blocks e.g. Richmond, QLD, 3121)
    LocalityId      INT NOT NULL
        CONSTRAINT FK_Customers_Localities REFERENCES dbo.Localities (LocalityId),

    -- E.164: '+' and up to 15 digits = 16 characters (ITU-T E.164)
    Phone           VARCHAR(16) NOT NULL
        CONSTRAINT CK_Customers_Phone
        CHECK (Phone LIKE '+%'
               AND LEN(Phone) BETWEEN 8 AND 16
               AND SUBSTRING(Phone, 2, 15) NOT LIKE '%[^0-9]%'),

    -- Encrypted code 1-6 (Sick, Healthy, Cancer, Deceased, Flu, Covid).
    -- One-character code -> every ciphertext has the same length (43 chars),
    -- so the length never reveals which status is stored.
    MedicalStatusEnc VARCHAR(48) NOT NULL
        CONSTRAINT CK_Customers_MedicalEnc CHECK (MedicalStatusEnc LIKE 'v%:%'),

    -- Encrypted card number (10-19 digits per ISO/IEC 7812-1, padded to 19)
    CardNumberEnc   VARCHAR(80) NOT NULL
        CONSTRAINT CK_Customers_CardEnc CHECK (CardNumberEnc LIKE 'v%:%'),

    -- Last four digits in clear for masked display (permitted by PCI DSS)
    CardLast4       CHAR(4) NOT NULL
        CONSTRAINT CK_Customers_CardLast4 CHECK (CardLast4 LIKE '[0-9][0-9][0-9][0-9]'),

    -- Encrypted MM/YY, separate field as the brief requires
    CardExpiryEnc   VARCHAR(64) NOT NULL
        CONSTRAINT CK_Customers_ExpiryEnc CHECK (CardExpiryEnc LIKE 'v%:%')
);
GO

-- Indexes for prefix searches ("starts with") on the searchable fields only.
-- Sensitive fields are encrypted and therefore never searchable (Guide 2.1).
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_Customers_LastName')
    CREATE INDEX IX_Customers_LastName  ON dbo.Customers (LastName);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_Customers_FirstName')
    CREATE INDEX IX_Customers_FirstName ON dbo.Customers (FirstName);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_Customers_Phone')
    CREATE INDEX IX_Customers_Phone     ON dbo.Customers (Phone);
GO
