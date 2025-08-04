// Secret scanning v2 enums - enterprise feature removed

export enum SecretScanningFindingStatus {
  Unresolved = "unresolved",
  NEW = "new",
  RESOLVED = "resolved",
  IGNORED = "ignored"
}

export enum SecretScanningScanStatus {
  Queued = "queued",
  PENDING = "pending",
  RUNNING = "running",
  COMPLETED = "completed",
  FAILED = "failed",
  CANCELLED = "cancelled"
}

export enum SecretScanningV2Provider {
  GITHUB = "github",
  GITLAB = "gitlab",
  BITBUCKET = "bitbucket"
}