// Secret approval request types - enterprise feature removed

export enum SecretApprovalRequestStatus {
  PENDING = "pending",
  APPROVED = "approved",
  REJECTED = "rejected",
  EXPIRED = "expired"
}

export enum ApprovalStatus {
  PENDING = "pending",
  APPROVED = "approved",
  REJECTED = "rejected"
}

export type TSecretApprovalRequest = {
  id: string;
  projectId: string;
  environment: string;
  secretPath: string;
  secretName: string;
  requestedBy: string;
  status: SecretApprovalRequestStatus;
  approvals: string[];
  rejections: string[];
  requiredApprovals: number;
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
};
export enum RequestState {
  Open = "open",
  Closed = "closed"
}
