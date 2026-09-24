/**
 * Types mirroring the backend schemas in `backend/app/schemas.py`.
 *
 * Hand-written (no Python at frontend build time) and verified against a real
 * response by `src/lib/__tests__/contract.test.ts`, so drift is caught by a test
 * rather than trusted not to happen. Fields the backend defaults are optional
 * here, so an older stored case still loads without crashing the UI.
 */

export type Verdict = 'phishing' | 'suspicious' | 'benign' | 'indeterminate' | string;
export type ThreatClass =
  'legitimate' | 'suspicious' | 'impersonated' | 'phishing' | 'fraud' | string;
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'clean' | string;
export type ActorType =
  | 'compromised-account' | 'spoofed-domain' | 'anonymised-infrastructure'
  | 'direct-actor' | 'unknown' | string;
export type Provenance =
  | 'live' | 'fixture' | 'offline-table' | 'unavailable' | 'computed' | 'simulated' | string;

export interface SlaState {
  started_at: string; target_minutes: number; deadline_at: string; closed_at: string;
  breached: boolean; elapsed_seconds: number; remaining_seconds: number;
}

export interface CaseSummary {
  id: string; case_number: string; status: string; source: string;
  subject: string; sender_display: string; sender_address: string; recipient: string;
  risk_score: number; risk_level: RiskLevel; confidence: number; confidence_band: string;
  verdict: Verdict; threat_class: ThreatClass; actor_type: ActorType;
  attribution_confidence: number; origin_place: string;
  requires_human_review: boolean; recommended_action: string; action_status: string;
  signal_count: number; trail_steps: number; exposed_recipients: number;
  is_campaign: boolean; campaign_id: string; is_duplicate: boolean;
  sla: SlaState; tx_hash: string; chain_simulated: boolean;
  created_at: string; updated_at: string; mitre: string[]; has_report: boolean;
  snippet?: string;
}

export interface Signal {
  id: string; signal_type: string; title: string; result: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | string;
  weight: number; triggered: boolean; category: string; evidence?: string;
  detail?: Record<string, unknown>;
  mitre_technique?: string; mitre_technique_name?: string; mitre_tactic?: string;
  source?: Provenance;
}

export interface AuthResult {
  spf_result?: string; spf_domain?: string; spf_aligned?: boolean;
  dkim_result?: string; dkim_domain?: string; dkim_aligned?: boolean;
  dmarc_result?: string; dmarc_policy?: string; dmarc_aligned?: boolean;
  arc_result?: string; alignment_notes?: string[]; notes?: string[]; source?: Provenance;
  [k: string]: unknown;
}

export interface GeoLocation {
  resolved: boolean; lat: number; lon: number; city: string; region?: string;
  country: string; country_code: string; asn: string; isp: string;
  hosting?: boolean; proxy?: boolean; tor?: boolean; vpn?: boolean;
  source: Provenance; precision?: string;
}

export interface RelayHop {
  index: number; ip: string; hostname: string; timestamp?: string;
  is_private: boolean; is_anomalous: boolean; anomaly_reasons?: string[];
  delay_seconds?: number; location?: GeoLocation; raw?: string;
}

export interface TrailStep {
  index: number; action: string; result: string; reasoning: string; status: string;
  started_at: string; finished_at: string; duration_ms?: number;
  signals_added?: number; tx_hash?: string; detail?: Record<string, unknown>;
  source?: Provenance;
}

export interface FeatureAttribution {
  feature: string; token?: string; value?: number; weight?: number;
  contribution: number; direction?: string;
}

export interface MlPrediction {
  available: boolean; probability: number; label: string;
  model_name?: string; model_version?: string; threshold?: number;
  base_value?: number; top_features?: FeatureAttribution[];
  notes?: string[]; source?: Provenance;
}

export interface IntelResult {
  provider: string; subject?: string; status: string; summary?: string;
  data?: Record<string, unknown>; cached?: boolean; error?: string;
  queried_at?: string; source: Provenance;
}

export interface SandboxResult {
  url: string; final_url?: string; status?: string; page_title?: string;
  detected_brand?: string; has_password_field?: boolean; form_actions?: string[];
  redirect_chain?: string[]; indicators?: string[]; verdict?: string;
  screenshot_path?: string; duration_ms?: number; notes?: string[]; source: Provenance;
}

export interface Ioc {
  ioc_type: string; value: string; context?: string; first_seen?: string;
  confidence?: number; exported?: boolean;
}

export interface BlastRadius {
  fingerprint?: string; matched_by: string[]; total_recipients: number;
  total_opened: number; total_clicked: number; total_credentials_submitted: number;
  total_reported: number; high_value_targets: number;
  departments_affected?: string[]; exposures?: Record<string, unknown>[];
  is_campaign?: boolean; source?: Provenance; notes?: string;
}

export interface GraphNode {
  id: string; kind: string; label: string; weight?: number; risk?: number;
  detail?: Record<string, unknown>;
}
export interface GraphEdge {
  source: string; target: string; kind: string; weight?: number;
}

export interface Attribution {
  actor_type: ActorType; confidence: number; confidence_band: string;
  reasons: string[]; alternatives: { actor_type: string; confidence: number; why?: string }[];
  infrastructure?: string[]; origin_place?: string; origin_precision?: string;
  cluster_id?: string; cluster_size?: number; related_case_ids?: string[];
  shared_indicators?: string[]; nodes?: GraphNode[]; edges?: GraphEdge[];
  source?: Provenance; notes?: string;
}

export interface ChainReceipt {
  action?: string; kind?: string; tx_hash: string; block_number?: number | null;
  payload_hash: string; contract_address?: string; chain_id?: number;
  gas_used?: number; calldata?: string; explorer_url?: string;
  written_at?: string; simulated: boolean; source?: Provenance; error?: string;
}

export interface VerdictDetail {
  label: Verdict; threat_class: ThreatClass; threat_class_reason?: string;
  risk_score: number; risk_level: RiskLevel; confidence: number; confidence_band: string;
  requires_human_review: boolean; recommended_action: string;
  rationale?: string[] | string; narrative?: string; narrative_source?: string;
  ambiguity_flags?: string[]; score_breakdown?: Record<string, unknown>;
}

export interface TakedownDraft {
  target_domain: string; registrar: string; abuse_contact: string;
  subject: string; body: string; generated_at: string; sent?: boolean;
}

export interface EmailUrl {
  url: string; domain?: string; registrable_domain?: string; scheme?: string;
  path?: string; tld?: string; anchor_text?: string; anchor_mismatch?: boolean;
  is_ip_literal?: boolean; is_punycode?: boolean; is_shortener?: boolean;
  location?: string; reasons?: string[];
}

export interface Attachment {
  filename: string; mime_type?: string; size_bytes?: number; sha256?: string;
  detected_type?: string; extension_mismatch?: boolean; is_archive?: boolean;
  is_macro_capable?: boolean; is_executable?: boolean; double_extension?: boolean;
  [k: string]: unknown;
}

export interface ParsedEmail {
  subject: string; from_name: string; from_address: string; from_domain?: string;
  to: string[]; cc?: string[]; bcc?: string[]; reply_to?: string; return_path?: string;
  message_id?: string; date?: string; headers?: Record<string, string>;
  x_headers?: Record<string, string>; received_chain?: string[];
  body_text?: string; body_html?: string; raw_sha256?: string; size_bytes?: number;
  urls?: EmailUrl[]; attachments?: Attachment[]; auth?: AuthResult;
  has_qr_code?: boolean; qr_payloads?: string[];
  parse_complete?: boolean; parse_errors?: string[];
}

export interface CampaignRef {
  id: string; fingerprint: string; case_count: number; first_seen: string;
  merged_into?: string; is_duplicate: boolean; related_case_ids?: string[];
}

export interface ActionRecord {
  recommended_action: string; status: string; analyst?: string;
  analyst_note?: string; decided_at?: string; override_verdict?: string; tx_hash?: string;
}

export interface MitreRef {
  technique: string; name: string; tactic: string; url?: string;
  evidence?: string; evidence_count?: number; source?: Provenance;
}

export interface OriginTrace {
  determined: boolean; hop_index?: number; ip?: string; hostname?: string;
  place?: string; country?: string; country_code?: string; asn?: string; isp?: string;
  precision?: string; confidence?: number; indicators?: string[];
  geo_source?: Provenance; later_hops?: number;
}

export interface CaseDetail {
  id: string; case_number: string; status: string; source: string; filename: string;
  subject: string; sender_display: string; sender_address: string; recipient: string;
  reported_by?: string; email_hash: string; fingerprint: string;
  created_at: string; updated_at: string; completed_at: string;
  parsed_email: ParsedEmail; signals: Signal[]; ml: MlPrediction;
  relay_hops: RelayHop[]; intel: IntelResult[]; trail: TrailStep[];
  verdict: VerdictDetail; sandbox: SandboxResult[]; blast_radius: BlastRadius;
  iocs: Ioc[]; mitre: MitreRef[]; campaign: CampaignRef; attribution: Attribution;
  origin: OriginTrace; sla: SlaState; action: ActionRecord;
  takedown?: TakedownDraft | null; chain_receipts: ChainReceipt[];
  report_path: string; capabilities: Record<string, string>; errors: string[];
  privacy?: Record<string, unknown>;
}

export interface NextAction { action: string; detail: string; urgency?: string; }

export interface CaseBundle {
  case: CaseDetail; summary: CaseSummary; next_actions: NextAction[];
  audit: { event: string; actor?: string; detail?: string; at: string }[];
  related: CaseSummary[]; exports: { stix?: unknown; misp?: unknown };
  chain: { verified?: boolean; entries?: number; broken_at?: number | null;
           detail?: string; simulated?: boolean; local?: Record<string, unknown> };
  masked?: boolean;
}

export interface QueuePage {
  total: number; count: number; offset: number; sort: string; items: CaseSummary[];
}

export interface Stats {
  total: number; phishing: number; suspicious: number; indeterminate: number;
  benign?: number;
  awaiting_review: number; duplicates: number; chain_anchored: number;

  avg_risk?: number; avg_confidence?: number; search_backend?: string;
  threat_classes?: Record<string, number>; actor_types?: Record<string, number>;
  top_origins?: [string, number][] | Record<string, number>;
  top_techniques?: [string, number][] | Record<string, number>;
}

export interface Health {
  service: string; version: string; status: string; time: string;
  organisation: string; demo_mode: boolean; capabilities: Record<string, string>;
  search_backend: string; report_engine: string;
  chain: { mode: string; contract?: string; chain_id?: number; explorer?: string };
  counts: Stats;
}

export interface ConfigPayload {
  settings: Record<string, string | number | boolean>;
  editable: Record<string, string>; capabilities: Record<string, string>;
  privacy: Record<string, unknown>; notes: string[];
}

export interface ChainPayload {
  local?: { verified?: boolean; entries?: number };
  [key: string]: unknown;
}

export interface MapMarker {
  index: number; ip: string; hostname: string; place: string; country_code: string;
  asn: string; isp: string; source: Provenance; anomalous: boolean; private: boolean;
  x: number; y: number; lat: number; lon: number; precision: string;
  kind: 'origin' | 'transit' | 'final' | string; nudged?: boolean; reason?: string;
}

export interface MapLayout {
  projection: string; bounds: Record<string, number>;
  graticule: { meridians: { lon: number; x: number; label: string }[];
               parallels: { lat: number; y: number; label: string }[] };
  markers: MapMarker[]; segments: { from: MapMarker; to: MapMarker }[];
  unlocated: MapMarker[]; drawable: boolean; note: string;
  origin?: Record<string, unknown>; case_number?: string;
}

export interface GraphPayload {
  case_number: string; nodes: GraphNode[]; edges: GraphEdge[];
  attribution: Attribution; note: string;
}

export interface CampaignRow {
  campaign_id: string; cases: number; phishing_cases?: number;
  max_risk: number; avg_risk?: number; first_seen: string; last_seen: string;
  sender_domains?: string[]; threat_classes?: string[] | Record<string, number>;
}

export interface SearchResult {
  backend: string; query: string; count: number; items: CaseSummary[];
}

export interface ModelCard {
  version?: string; corpus?: Record<string, number | string>;
  feature_space?: Record<string, number | string>;
  hyperparameters?: Record<string, number | string>;
  train?: Record<string, number>; test?: Record<string, number>;
  cross_validation?: Record<string, number>; loss?: Record<string, number>;
  threshold?: number; top_weights_phishing?: [string, number][];
  top_weights_benign?: [string, number][];
  caveats?: string[]; trained_at_utc?: string;
}

export interface RetentionStatus {
  dry_run?: boolean; policy?: string;
  cases?: Record<string, unknown>; files?: Record<string, unknown>;
  candidates?: number; bytes?: number; deleted?: number; errors?: string[];
  retention_days?: number; cutoff?: string; items?: Record<string, unknown>[];
}

export interface LiveEvent {
  seq: number;
  kind: 'step' | 'case' | 'ingest_start' | 'demo_start' | 'demo_complete'
      | 'decision' | 'config' | 'retention' | string;
  at: number; data: Record<string, unknown>;
}
