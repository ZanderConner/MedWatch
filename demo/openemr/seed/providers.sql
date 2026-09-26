-- Seeds the four referring/ordering physicians referenced by
-- simulators/patients.csv (and therefore by every HL7 order the
-- hl7-order-generator produces) as real OpenEMR provider users, so
-- appointments and lab orders can be attributed to a real provider_id
-- instead of falling back to the built-in admin account.
--
-- NPIs are obviously-fake 10-digit placeholders (100000000x), not real
-- National Provider Identifiers.

INSERT INTO users (
  username, password, authorized, fname, lname, active, npi, title,
  specialty, facility_id, calendar, main_menu_role, patient_menu_role,
  see_auth, abook_type, default_warehouse, irnpool, taxonomy
)
SELECT s.username, s.password, s.authorized, s.fname, s.lname, s.active,
       s.npi, s.title, s.specialty, s.facility_id, s.calendar,
       s.main_menu_role, s.patient_menu_role, s.see_auth, s.abook_type,
       s.default_warehouse, s.irnpool, s.taxonomy
FROM (
  SELECT
    'dr.patel' AS username, '' AS password, 1 AS authorized,
    'Priya' AS fname, 'Patel' AS lname, 1 AS active,
    '1000000001' AS npi, 'MD' AS title, 'Internal Medicine' AS specialty,
    3 AS facility_id, 1 AS calendar, 'standard' AS main_menu_role,
    'standard' AS patient_menu_role, 1 AS see_auth, '' AS abook_type,
    '' AS default_warehouse, '' AS irnpool, '207R00000X' AS taxonomy
  UNION ALL
  SELECT
    'dr.garcia', '', 1,
    'Luis', 'Garcia', 1,
    '1000000002', 'MD', 'Family Medicine',
    3, 1, 'standard',
    'standard', 1, '',
    '', '', '207Q00000X'
  UNION ALL
  SELECT
    'dr.chen', '', 1,
    'Wei', 'Chen', 1,
    '1000000003', 'MD', 'Hematology',
    3, 1, 'standard',
    'standard', 1, '',
    '', '', '207RH0000X'
  UNION ALL
  SELECT
    'dr.thompson', '', 1,
    'James', 'Thompson', 1,
    '1000000004', 'MD', 'Internal Medicine',
    3, 1, 'standard',
    'standard', 1, '',
    '', '', '207R00000X'
) AS s
WHERE NOT EXISTS (SELECT 1 FROM users existing WHERE existing.username = s.username);
