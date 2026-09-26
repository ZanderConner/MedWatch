-- Seeds a handful of scheduled appointments for the demo patient pool, so
-- OpenEMR's calendar isn't empty out of the box. One "Office Visit" per
-- patient with their assigned provider, spread over the next 14 days
-- during business hours (09:00-16:00, Mon-Fri).
--
-- Idempotent: skipped for a patient that already has any appointment
-- (checked by pc_pid).

INSERT INTO openemr_postcalendar_events (
  pc_catid, pc_multiple, pc_aid, pc_pid, pc_title, pc_time,
  pc_hometext, pc_eventDate, pc_duration, pc_startTime, pc_endTime,
  pc_facility, pc_apptstatus
)
SELECT
  5,                                  -- category: Office Visit
  0,
  pd.providerID,
  pd.pid,
  'Office Visit',
  NOW(),
  'Scheduled via medSim demo-data seed.',
  DATE_ADD(CURDATE(), INTERVAL (1 + (pd.pid % 14)) DAY),
  900,                                -- 15 minutes
  SEC_TO_TIME(32400 + ((pd.pid * 1300) % 25200)),  -- 09:00-16:00 spread
  SEC_TO_TIME(33300 + ((pd.pid * 1300) % 25200)),
  3,                                  -- facility id seeded by OpenEMR install
  '-'
FROM patient_data pd
WHERE pd.pubpid LIKE 'MRN1%'
  AND pd.providerID IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM openemr_postcalendar_events existing
    WHERE existing.pc_pid = pd.pid
  );
