import { z } from "zod";

export const SSHHostSchema = z.object({
  id: z.string().uuid(),
  projectId: z.string().uuid(),
  hostname: z.string(),
  ipAddress: z.string().ip().optional(),
  port: z.number().int().positive().default(22),
  username: z.string().optional(),
  publicKey: z.string().optional(),
  fingerprint: z.string().optional(),
  tags: z.array(z.string()).default([]),
  status: z.enum(["active", "inactive", "unreachable"]).default("active"),
  lastSeen: z.date().optional(),
  createdAt: z.date(),
  updatedAt: z.date()
});

export const CreateSSHHostSchema = z.object({
  projectId: z.string().uuid(),
  hostname: z.string(),
  ipAddress: z.string().ip().optional(),
  port: z.number().int().positive().default(22),
  username: z.string().optional(),
  publicKey: z.string().optional(),
  tags: z.array(z.string()).default([])
});

export const UpdateSSHHostSchema = z.object({
  hostname: z.string().optional(),
  ipAddress: z.string().ip().optional(),
  port: z.number().int().positive().optional(),
  username: z.string().optional(),
  publicKey: z.string().optional(),
  tags: z.array(z.string()).optional(),
  status: z.enum(["active", "inactive", "unreachable"]).optional()
});

export const SSHHostListSchema = z.object({
  projectId: z.string().uuid(),
  status: z.enum(["active", "inactive", "unreachable"]).optional(),
  tags: z.array(z.string()).optional(),
  limit: z.number().positive().default(20),
  offset: z.number().nonnegative().default(0)
});

export const sanitizedSshHost = SSHHostSchema.omit({
  projectId: true
});

export const loginMappingSchema = z.object({
  username: z.string(),
  uid: z.number().int().positive().optional(),
  gid: z.number().int().positive().optional(),
  groups: z.array(z.string()).default([])
});

export type TSSHHost = z.infer<typeof SSHHostSchema>;
export type TCreateSSHHost = z.infer<typeof CreateSSHHostSchema>;
export type TUpdateSSHHost = z.infer<typeof UpdateSSHHostSchema>;