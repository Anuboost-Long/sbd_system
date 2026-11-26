/* =============================================================================
   04_seed_localities.sql  (CustomerDb)
   Run as: deployment account.

   A small sample of real Australian localities for the demo. Richmond appears
   in three states with different postcodes, which lets the tests show that the
   database refuses an invalid combination (e.g. Richmond, QLD, 3121).
   Customer records are NOT seeded here: their sensitive fields must be
   encrypted by the API, so the API seed command loads them (synthetic data and
   test card numbers only).
   ============================================================================= */
USE CustomerDb;
GO

MERGE dbo.Localities AS target
USING (VALUES
    (N'Richmond',         'VIC', '3121'),
    (N'Richmond',         'NSW', '2753'),
    (N'Richmond',         'QLD', '4822'),
    (N'Carlton',          'VIC', '3053'),
    (N'Fitzroy',          'VIC', '3065'),
    (N'Parramatta',       'NSW', '2150'),
    (N'Bondi',            'NSW', '2026'),
    (N'Fortitude Valley', 'QLD', '4006'),
    (N'Glenelg',          'SA',  '5045'),
    (N'Fremantle',        'WA',  '6160'),
    (N'Sandy Bay',        'TAS', '7005'),
    (N'Darwin City',      'NT',  '0800'),
    (N'Braddon',          'ACT', '2612')
) AS source (Suburb, State, Postcode)
ON  target.Suburb = source.Suburb
AND target.State = source.State
AND target.Postcode = source.Postcode
WHEN NOT MATCHED THEN
    INSERT (Suburb, State, Postcode) VALUES (source.Suburb, source.State, source.Postcode);
GO
