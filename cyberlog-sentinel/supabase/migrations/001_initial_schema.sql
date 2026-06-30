-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Profiles (extends Supabase auth.users)
CREATE TABLE IF NOT EXISTS profiles (
  id UUID REFERENCES auth.users ON DELETE CASCADE PRIMARY KEY,
  full_name TEXT,
  role TEXT DEFAULT 'analyst' CHECK (role IN ('analyst', 'senior_analyst', 'soc_lead')),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can view own profile" ON profiles FOR SELECT USING (auth.uid() = id);
CREATE POLICY "Users can update own profile" ON profiles FOR UPDATE USING (auth.uid() = id);

-- Trigger: auto-create profile on signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger AS $$
BEGIN
  INSERT INTO public.profiles (id, full_name)
  VALUES (new.id, new.raw_user_meta_data->>'full_name');
  RETURN new;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE PROCEDURE public.handle_new_user();

-- Upload jobs
CREATE TABLE IF NOT EXISTS upload_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE,
  filename TEXT NOT NULL,
  file_size_bytes BIGINT,
  storage_path TEXT,
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'complete', 'failed')),
  total_lines INT,
  parsed_lines INT DEFAULT 0,
  error_message TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

ALTER TABLE upload_jobs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users see own upload jobs" ON upload_jobs FOR ALL USING (auth.uid() = user_id);

-- Log events
CREATE TABLE IF NOT EXISTS log_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id UUID REFERENCES upload_jobs(id) ON DELETE CASCADE,
  timestamp TIMESTAMPTZ NOT NULL,
  hostname TEXT,
  service TEXT,
  pid INT,
  event_type TEXT NOT NULL,
  username TEXT,
  source_ip INET,
  source_port INT,
  auth_method TEXT,
  outcome TEXT CHECK (outcome IN ('success', 'failure', 'unknown')),
  raw_line TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  mitre_technique_id TEXT,
  mitre_technique_name TEXT,
  mitre_tactic TEXT,
  threat_tags TEXT[] DEFAULT '{}',
  session_id TEXT,
  geo_country TEXT,
  geo_city TEXT,
  is_internal_ip BOOLEAN DEFAULT FALSE,
  analyst_note TEXT,
  is_false_positive BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE log_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users see events from own jobs" ON log_events FOR ALL
  USING (EXISTS (SELECT 1 FROM upload_jobs WHERE upload_jobs.id = log_events.job_id AND upload_jobs.user_id = auth.uid()));

CREATE INDEX IF NOT EXISTS idx_log_events_job_id ON log_events(job_id);
CREATE INDEX IF NOT EXISTS idx_log_events_timestamp ON log_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_log_events_source_ip ON log_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_log_events_severity ON log_events(severity);
CREATE INDEX IF NOT EXISTS idx_log_events_event_type ON log_events(event_type);
CREATE INDEX IF NOT EXISTS idx_log_events_outcome ON log_events(outcome);
CREATE INDEX IF NOT EXISTS idx_log_events_username ON log_events(username);

-- Threat incidents
CREATE TABLE IF NOT EXISTS incidents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id UUID REFERENCES upload_jobs(id) ON DELETE CASCADE,
  incident_ref TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  status TEXT DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'closed', 'false_positive')),
  mitre_technique_id TEXT,
  mitre_tactic TEXT,
  source_ips TEXT[] DEFAULT '{}',
  targeted_users TEXT[] DEFAULT '{}',
  event_count INT DEFAULT 0,
  first_seen TIMESTAMPTZ,
  last_seen TIMESTAMPTZ,
  assigned_to UUID REFERENCES profiles(id),
  analyst_notes TEXT,
  is_false_positive BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users see own incidents" ON incidents FOR ALL
  USING (EXISTS (SELECT 1 FROM upload_jobs WHERE upload_jobs.id = incidents.job_id AND upload_jobs.user_id = auth.uid()));

CREATE INDEX IF NOT EXISTS idx_incidents_job_id ON incidents(job_id);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);

-- Detections
CREATE TABLE IF NOT EXISTS detections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id UUID REFERENCES upload_jobs(id) ON DELETE CASCADE,
  rule_id TEXT NOT NULL,
  rule_name TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence INT CHECK (confidence BETWEEN 0 AND 100),
  source_ip INET,
  username TEXT,
  event_ids UUID[] DEFAULT '{}',
  mitre_technique_id TEXT,
  details JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE detections ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users see own detections" ON detections FOR ALL
  USING (EXISTS (SELECT 1 FROM upload_jobs WHERE upload_jobs.id = detections.job_id AND upload_jobs.user_id = auth.uid()));

CREATE INDEX IF NOT EXISTS idx_detections_job_id ON detections(job_id);

-- SSH Sessions
CREATE TABLE IF NOT EXISTS ssh_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id UUID REFERENCES upload_jobs(id) ON DELETE CASCADE,
  session_key TEXT,
  username TEXT,
  source_ip INET,
  login_time TIMESTAMPTZ,
  logout_time TIMESTAMPTZ,
  duration_seconds INT,
  sudo_commands TEXT[] DEFAULT '{}',
  status TEXT DEFAULT 'closed' CHECK (status IN ('active', 'closed')),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE ssh_sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users see own sessions" ON ssh_sessions FOR ALL
  USING (EXISTS (SELECT 1 FROM upload_jobs WHERE upload_jobs.id = ssh_sessions.job_id AND upload_jobs.user_id = auth.uid()));

-- IP Watchlist
CREATE TABLE IF NOT EXISTS ip_watchlist (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE,
  ip_address INET NOT NULL,
  label TEXT,
  is_whitelist BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, ip_address)
);

ALTER TABLE ip_watchlist ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users manage own watchlist" ON ip_watchlist FOR ALL USING (auth.uid() = user_id);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES profiles(id),
  action TEXT NOT NULL,
  resource_type TEXT,
  resource_id UUID,
  details JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users see own audit log" ON audit_log FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "System can insert audit log" ON audit_log FOR INSERT WITH CHECK (true);

-- Create Supabase storage bucket
INSERT INTO storage.buckets (id, name, public) VALUES ('log-uploads', 'log-uploads', false) ON CONFLICT DO NOTHING;

CREATE POLICY "Users upload to own folder" ON storage.objects
  FOR INSERT WITH CHECK (bucket_id = 'log-uploads' AND auth.uid()::text = (storage.foldername(name))[1]);

CREATE POLICY "Users read own uploads" ON storage.objects
  FOR SELECT USING (bucket_id = 'log-uploads' AND auth.uid()::text = (storage.foldername(name))[1]);
