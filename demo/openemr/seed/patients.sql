CREATE TEMPORARY TABLE IF NOT EXISTS medsim_seed_patients (
  pubpid VARCHAR(64) PRIMARY KEY,
  fname VARCHAR(255),
  mname VARCHAR(255),
  lname VARCHAR(255),
  DOB DATE,
  sex VARCHAR(32),
  provider_username VARCHAR(64)
);

-- provider_username matches the referring_physician round-robin used in
-- simulators/patients.csv, so each seeded patient's PCP is the same
-- physician the HL7 order generator names as the ordering provider.
INSERT IGNORE INTO medsim_seed_patients (pubpid, fname, mname, lname, DOB, sex, provider_username) VALUES
('MRN10042','CHRISTOPHER','','MORALES','1996-12-28','Male','dr.patel'),
('MRN10043','MICHAEL','','SMITH','1954-10-23','Male','dr.garcia'),
('MRN10044','WILLIAM','S','BREWER','1941-05-18','Male','dr.chen'),
('MRN10045','STEVE','','ROY','1989-05-17','Male','dr.thompson'),
('MRN10046','DIANA','','SANDOVAL','1959-10-10','Female','dr.patel'),
('MRN10047','DEREK','','GARCIA','1991-06-11','Male','dr.garcia'),
('MRN10048','JON','J','OCONNOR','2002-03-15','Male','dr.chen'),
('MRN10049','ROBERT','','MCLAUGHLIN','1964-11-28','Male','dr.thompson'),
('MRN10050','SUSAN','','BATES','2005-03-01','Female','dr.patel'),
('MRN10051','DOUGLAS','','JONES','2019-06-23','Male','dr.garcia'),
('MRN10052','SARAH','','WILLIAMS','2005-04-02','Female','dr.chen'),
('MRN10053','CHRISTOPHER','K','MENDOZA','1957-12-17','Male','dr.thompson'),
('MRN10054','SOPHIA','U','HANSON','1953-05-21','Female','dr.patel'),
('MRN10055','BRANDI','','POWELL','1955-02-18','Female','dr.garcia'),
('MRN10056','THOMAS','','CHARLES','1959-07-06','Male','dr.chen'),
('MRN10057','SYDNEY','','DANIELS','2005-02-14','Female','dr.thompson'),
('MRN10058','SHERRY','G','WILSON','1962-05-23','Female','dr.patel'),
('MRN10059','KRISTA','','WOODWARD','1977-06-28','Female','dr.garcia'),
('MRN10060','JESUS','','HOOD','1994-07-23','Male','dr.chen'),
('MRN10061','ANGELA','H','JONES','1992-07-04','Female','dr.thompson'),
('MRN10062','RODNEY','','PHILLIPS','1989-05-18','Male','dr.patel'),
('MRN10063','MARK','','COX','1977-07-15','Male','dr.garcia'),
('MRN10064','WENDY','H','MOORE','1988-09-06','Female','dr.chen'),
('MRN10065','MICHELE','','JACOBS','1963-08-28','Female','dr.thompson'),
('MRN10066','RODNEY','B','MILLER','2009-01-26','Male','dr.patel'),
('MRN10067','MITCHELL','L','RUIZ','1960-05-05','Male','dr.garcia'),
('MRN10068','TIMOTHY','T','BROWN','1975-11-02','Male','dr.chen'),
('MRN10069','ROBERT','R','GOODWIN','1968-12-25','Male','dr.thompson'),
('MRN10070','JACQUELINE','','BUTLER','1965-11-05','Female','dr.patel');

INSERT INTO patient_data (pid, pubpid, fname, mname, lname, DOB, sex, date, providerID)
SELECT
  COALESCE((SELECT MAX(existing.pid) FROM patient_data existing), 0)
    + ROW_NUMBER() OVER (ORDER BY seed.pubpid),
  seed.pubpid,
  seed.fname,
  seed.mname,
  seed.lname,
  seed.DOB,
  seed.sex,
  NOW(),
  (SELECT id FROM users WHERE username = seed.provider_username)
FROM medsim_seed_patients seed
WHERE NOT EXISTS (
  SELECT 1 FROM patient_data existing
  WHERE existing.pubpid = seed.pubpid
);
