import { z } from "zod";

export const SSHCertificateSchema = z.object({
  id: z.string().uuid(),
  projectId: z.string().uuid(),
  publicKey: z.string(),
  privateKey: z.string(),
  status: z.enum(["active", "inactive"]).default("active"),
  createdAt: z.date(),
  updatedAt: z.date()
});

export const CreateSSHCertificateSchema = z.object({
  projectId: z.string().uuid(),
  name: z.string(),
  keyAlgorithm: z.enum(["rsa", "ecdsa", "ed25519"]).default("ed25519")
});

export const UpdateSSHCertificateSchema = z.object({
  name: z.string().optional(),
  status: z.enum(["active", "inactive"]).optional()
});

export const SSHCertificateListSchema = z.object({
  projectId: z.string().uuid(),
  limit: z.number().positive().default(20),
  offset: z.number().nonnegative().default(0)
});

export const sanitizedSshCertificate = SSHCertificateSchema.omit({
  privateKey: true,
  projectId: true
});

export type TSSHCertificate = z.infer<typeof SSHCertificateSchema>;
export type TCreateSSHCertificate = z.infer<typeof CreateSSHCertificateSchema>;
export type TUpdateSSHCertificate = z.infer<typeof UpdateSSHCertificateSchema>;