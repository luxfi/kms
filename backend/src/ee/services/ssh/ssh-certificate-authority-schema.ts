import { z } from "zod";

export const SSHCertificateAuthoritySchema = z.object({
  id: z.string().uuid(),
  projectId: z.string().uuid(),
  keyAlgorithm: z.enum(["rsa", "ecdsa", "ed25519"]),
  publicKey: z.string(),
  privateKey: z.string(),
  status: z.enum(["active", "inactive", "rotating"]),
  createdAt: z.date(),
  updatedAt: z.date()
});

export const CreateSSHCertificateAuthoritySchema = z.object({
  projectId: z.string().uuid(),
  keyAlgorithm: z.enum(["rsa", "ecdsa", "ed25519"]).default("ed25519"),
  friendlyName: z.string().optional()
});

export const UpdateSSHCertificateAuthoritySchema = z.object({
  status: z.enum(["active", "inactive"]).optional(),
  friendlyName: z.string().optional()
});

export const SSHCertificateRequestSchema = z.object({
  publicKey: z.string(),
  principalName: z.string(),
  ttl: z.number().positive(),
  certType: z.enum(["user", "host"]),
  keyId: z.string().optional(),
  validPrincipals: z.array(z.string()).optional(),
  extensions: z.record(z.string()).optional()
});

export const sanitizedSshCa = SSHCertificateAuthoritySchema.omit({
  privateKey: true,
  projectId: true
});