import { z } from "zod";

export const SSHHostGroupSchema = z.object({
  id: z.string().uuid(),
  projectId: z.string().uuid(),
  name: z.string(),
  description: z.string().optional(),
  hostIds: z.array(z.string().uuid()).default([]),
  tags: z.array(z.string()).default([]),
  createdAt: z.date(),
  updatedAt: z.date()
});

export const CreateSSHHostGroupSchema = z.object({
  projectId: z.string().uuid(),
  name: z.string(),
  description: z.string().optional(),
  hostIds: z.array(z.string().uuid()).default([]),
  tags: z.array(z.string()).default([])
});

export const UpdateSSHHostGroupSchema = z.object({
  name: z.string().optional(),
  description: z.string().optional(),
  hostIds: z.array(z.string().uuid()).optional(),
  tags: z.array(z.string()).optional()
});

export const sanitizedSshHostGroup = SSHHostGroupSchema.omit({
  projectId: true
});

export type TSSHHostGroup = z.infer<typeof SSHHostGroupSchema>;
export type TCreateSSHHostGroup = z.infer<typeof CreateSSHHostGroupSchema>;
export type TUpdateSSHHostGroup = z.infer<typeof UpdateSSHHostGroupSchema>;