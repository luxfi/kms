export enum EventType {
  SecretCreated = "secret.created",
  SecretUpdated = "secret.updated",
  SecretDeleted = "secret.deleted",
  SecretRotated = "secret.rotated",
  SecretSynced = "secret.synced",
  ProjectCreated = "project.created",
  ProjectUpdated = "project.updated",
  ProjectDeleted = "project.deleted",
  UserJoined = "user.joined",
  UserLeft = "user.left",
  PolicyViolation = "policy.violation",
  AccessDenied = "access.denied",
  ApprovalRequested = "approval.requested",
  ApprovalApproved = "approval.approved",
  ApprovalRejected = "approval.rejected"
}

export interface TEventPayload {
  type: EventType;
  timestamp: Date;
  actor: {
    id: string;
    type: "user" | "machine" | "system";
    name?: string;
  };
  resource: {
    id: string;
    type: string;
    name?: string;
  };
  metadata?: Record<string, any>;
}

export interface TEventFilter {
  types?: EventType[];
  resourceTypes?: string[];
  actorIds?: string[];
  startDate?: Date;
  endDate?: Date;
}
import { z } from "zod";
export const EventRegisterSchema = z.object({
  types: z.array(z.string()).optional(),
  resourceTypes: z.array(z.string()).optional()
});
