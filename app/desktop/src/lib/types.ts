export type ProfileSummary = {
  name: string;
  path: string;
  is_active: boolean;
  user_id?: string | null;
  device_id?: string | null;
};

export type IdentitySummaryView = {
  user_id: string;
  device_id: string;
  device_status: string;
  profile_path: string;
  mnemonic: string;
};

export type RuntimeStatusView = {
  mode?: string | null;
  deployment_bound: boolean;
  public_base_url?: string | null;
  worker_name?: string | null;
  provisioned_at?: string | null;
  last_error?: string | null;
};

export type CloudflarePreflightView = {
  workspace_root_found: boolean;
  service_root?: string | null;
  wrangler_available: boolean;
  wrangler_logged_in: boolean;
  runtime_bound: boolean;
  deployment_bundle_present: boolean;
  identity_ready: boolean;
  blocking_error?: string | null;
};

export type CloudflareRuntimeDetailsView = {
  mode?: string | null;
  deployment_bound: boolean;
  public_base_url?: string | null;
  worker_name?: string | null;
  provisioned_at?: string | null;
  last_error?: string | null;
  deploy_url?: string | null;
  deployment_region?: string | null;
  bucket_name?: string | null;
  preview_bucket_name?: string | null;
  service_root?: string | null;
  workspace_root?: string | null;
  deployment_bundle_path?: string | null;
  bootstrap_secret_present: boolean;
  sharing_secret_present: boolean;
};

export type CloudflareActionResultView = {
  action: string;
  updated_runtime: boolean;
  deployment_bound: boolean;
  banner: BannerView;
  runtime: CloudflareRuntimeDetailsView;
};

export type BannerView = {
  severity: string;
  message: string;
};

export type OnboardingStateView = {
  has_profiles: boolean;
  has_identity: boolean;
  has_runtime_binding: boolean;
  step: string;
};

export type AppBootstrapView = {
  profiles: ProfileSummary[];
  active_profile?: ProfileSummary | null;
  identity?: IdentitySummaryView | null;
  runtime?: RuntimeStatusView | null;
  onboarding: OnboardingStateView;
  banners: BannerView[];
};

export type ProvisionProgressView = {
  provisioned: boolean;
  mode: string;
  runtime: RuntimeStatusView;
  identity: IdentitySummaryView;
};

export type CloudflareDeployOverrides = {
  worker_name?: string | null;
  public_base_url?: string | null;
  deployment_region?: string | null;
  max_inline_bytes?: string | null;
  retention_days?: string | null;
  rate_limit_per_minute?: string | null;
  rate_limit_per_hour?: string | null;
  bucket_name?: string | null;
  preview_bucket_name?: string | null;
};

export type ContactDeviceView = {
  device_id: string;
  status: string;
};

export type ContactListItem = {
  user_id: string;
  device_count: number;
  has_conversation: boolean;
  identity_bundle_ref?: string | null;
};

export type ContactDetailView = {
  user_id: string;
  devices: ContactDeviceView[];
  identity_bundle_ref?: string | null;
  last_refresh_error?: string | null;
};

export type MessageRequestItemView = {
  request_id: string;
  recipient_device_id: string;
  sender_user_id: string;
  first_seen_at: number;
  last_seen_at: number;
  message_count: number;
  last_message_id: string;
  last_conversation_id: string;
};

export type MessageRequestActionView = {
  accepted: boolean;
  request_id: string;
  sender_user_id: string;
  promoted_count: number;
  action: string;
};

export type AllowlistView = {
  allowed_sender_user_ids: string[];
  rejected_sender_user_ids: string[];
};

export type ConversationListItem = {
  conversation_id: string;
  peer_user_id: string;
  conversation_state: string;
  recovery_status: string;
  last_message_preview?: string | null;
  last_message_type?: string | null;
  message_count: number;
};

export type ConversationDetailView = {
  conversation_id: string;
  peer_user_id: string;
  conversation_state: string;
  recovery_status: string;
  message_count: number;
  mls_status?: string | null;
  recovery?: {
    reason: string;
    phase: string;
    attempt_count: number;
    identity_refresh_retry_count: number;
    last_error?: string | null;
    escalation_reason?: string | null;
  } | null;
};

export type StorageRefView = {
  ref: string;
  mime_type: string;
  size_bytes: number;
};

export type MessageItemView = {
  conversation_id: string;
  message_id: string;
  sender_user_id?: string | null;
  direction: string;
  message_type: string;
  plaintext?: string | null;
  created_at?: string | null;
  storage_refs: StorageRefView[];
  has_attachment: boolean;
  attachment_count: number;
  downloaded_attachment_available: boolean;
  attachment_refs: StorageRefView[];
  primary_attachment_previewable: boolean;
  primary_attachment_local_path?: string | null;
  primary_attachment_display_name?: string | null;
};

export type SyncCheckpointView = {
  last_fetched_seq: number;
  last_acked_seq: number;
  pending_retry: boolean;
  pending_record_seqs: number[];
};

export type RecoveryConversationView = {
  conversation_id: string;
  recovery_status: string;
  reason: string;
  phase: string;
  attempt_count: number;
  identity_refresh_retry_count: number;
  pending_record_count: number;
  pending_record_seqs: number[];
  last_fetched_seq: number;
  last_acked_seq: number;
  mls_status?: string | null;
  escalation_reason?: string | null;
  last_error?: string | null;
};

export type SyncStatusView = {
  device_id?: string | null;
  checkpoint?: SyncCheckpointView | null;
  pending_outbox: number;
  pending_blob_uploads: number;
  recovery_conversations: RecoveryConversationView[];
};

export type RealtimeStatusView = {
  device_id?: string | null;
  connected: boolean;
  last_known_seq: number;
  needs_reconnect: boolean;
};

export type AppendResultSummary = {
  accepted: boolean;
  delivered_to: string;
  queued_as_request?: boolean | null;
  request_id?: string | null;
  seq?: number | null;
};

export type SendMessageResultView = {
  conversation_id: string;
  pending_outbox: number;
  append_result?: AppendResultSummary | null;
  latest_notification?: string | null;
};

export type AttachmentTransferView = {
  transfer_id: string;
  task_kind: string;
  conversation_id: string;
  scope: string;
  message_id?: string | null;
  file_name?: string | null;
  reference?: string | null;
  state: string;
  retryable?: boolean | null;
  detail?: string | null;
  progress_label?: string | null;
  destination_path?: string | null;
  opened?: boolean | null;
};

export type SendAttachmentResultView = {
  conversation_id: string;
  file_name: string;
  pending_outbox: number;
  pending_blob_uploads: number;
  append_result?: AppendResultSummary | null;
  latest_notification?: string | null;
};

export type DownloadAttachmentResultView = {
  conversation_id: string;
  message_id: string;
  destination: string;
  downloaded: boolean;
};

export type BatchSendAttachmentResultView = {
  conversation_id: string;
  queued_count: number;
  results: SendAttachmentResultView[];
  pending_blob_uploads: number;
  latest_notification?: string | null;
};

export type BackgroundDownloadTicketView = {
  transfer_id: string;
  conversation_id: string;
  message_id: string;
  destination: string;
  started: boolean;
};

export type AttachmentPreviewView = {
  kind: string;
  mime_type: string;
  display_name: string;
  local_path?: string | null;
  message_id: string;
};

export type DirectShellView = {
  contacts: ContactListItem[];
  conversations: ConversationListItem[];
  selected_contact?: ContactDetailView | null;
  selected_conversation?: ConversationDetailView | null;
  messages: MessageItemView[];
  sync: SyncStatusView;
  realtime: RealtimeStatusView;
  attachment_transfers: AttachmentTransferView[];
  banners: BannerView[];
};
