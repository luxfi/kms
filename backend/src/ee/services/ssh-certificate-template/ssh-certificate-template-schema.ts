import { z } from "zod";

export const SSHCertificateTemplateSchema = z.object({
  id: z.string().uuid(),
  projectId: z.string().uuid(),
  sshCaId: z.string().uuid(),
  name: z.string(),
  ttl: z.string().default("1h"),
  maxTTL: z.string().default("24h"),
  allowedUsers: z.array(z.string()).default([]),
  allowedHosts: z.array(z.string()).default([]),
  allowedPrincipals: z.array(z.string()).default([]),
  allowUserCertificates: z.boolean().default(true),
  allowHostCertificates: z.boolean().default(false),
  createdAt: z.date(),
  updatedAt: z.date()
});

export const CreateSSHCertificateTemplateSchema = z.object({
  projectId: z.string().uuid(),
  sshCaId: z.string().uuid(),
  name: z.string(),
  ttl: z.string().default("1h"),
  maxTTL: z.string().default("24h"),
  allowedUsers: z.array(z.string()).default([]),
  allowedHosts: z.array(z.string()).default([]),
  allowedPrincipals: z.array(z.string()).default([]),
  allowUserCertificates: z.boolean().default(true),
  allowHostCertificates: z.boolean().default(false)
});

export const UpdateSSHCertificateTemplateSchema = z.object({
  name: z.string().optional(),
  ttl: z.string().optional(),
  maxTTL: z.string().optional(),
  allowedUsers: z.array(z.string()).optional(),
  allowedHosts: z.array(z.string()).optional(),
  allowedPrincipals: z.array(z.string()).optional(),
  allowUserCertificates: z.boolean().optional(),
  allowHostCertificates: z.boolean().optional()
});

export const sanitizedSshCertificateTemplate = SSHCertificateTemplateSchema.omit({
  projectId: true
});

export type TSSHCertificateTemplate = z.infer<typeof SSHCertificateTemplateSchema>;
export type TCreateSSHCertificateTemplate = z.infer<typeof CreateSSHCertificateTemplateSchema>;
export type TUpdateSSHCertificateTemplate = z.infer<typeof UpdateSSHCertificateTemplateSchema>;