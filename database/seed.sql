-- =============================================================================
-- AI SOC Copilot - Idempotent Baseline Seed Data
-- Safe to execute repeatedly without duplicating reference records.
-- =============================================================================

-- 1. SEED MITRE ATT&CK TECHNIQUES (IDEMPOTENT)
INSERT INTO mitre_techniques (technique_id, name, tactic, description)
VALUES 
  ('T1110', 'Brute Force', 'Credential Access', 'Adversaries may use brute force techniques to attempt credential access through trial and error guessing of passwords or tokens.'),
  ('T1046', 'Network Service Scanning', 'Discovery', 'Adversaries may attempt to get a listing of services running on remote hosts by probing ports across network segments.'),
  ('T1059', 'Command and Scripting Interpreter', 'Execution', 'Adversaries may abuse command and script interpreters such as PowerShell, Bash, or cmd.exe to execute arbitrary code.'),
  ('T1071', 'Application Layer Protocol', 'Command and Control', 'Adversaries may communicate using application layer protocols (HTTP, HTTPS, DNS) to blend in with legitimate network traffic.'),
  ('T1190', 'Exploit Public-Facing Application', 'Initial Access', 'Adversaries may attempt to exploit a vulnerability in an Internet-facing computer or program to gain initial entry.'),
  ('T1078', 'Valid Accounts', 'Defense Evasion', 'Adversaries may obtain and abuse credentials of existing accounts as a means of maintaining access and circumventing access controls.')
ON CONFLICT (technique_id) DO UPDATE 
SET name = EXCLUDED.name,
    tactic = EXCLUDED.tactic,
    description = EXCLUDED.description;

-- 2. SEED DEFAULT SOC ANALYST USER (IDEMPOTENT)
INSERT INTO users (username, email, password_hash, role)
VALUES (
  'analyst_soc',
  'analyst@soc-copilot.internal',
  '$2b$12$e8YqAOmrIevvTzK9o6NqP.uU85qVp7c4gDlh4j1z9bW0Gv8xK4eCe',
  'analyst'
)
ON CONFLICT (username) DO NOTHING;
