import { TDbClient } from "@app/db";
import { TableName } from "@app/db/schemas";
import { ormify } from "@app/lib/knex";

export type TSshCertificateAuthorityDALFactory = ReturnType<typeof sshCertificateAuthorityDALFactory>;

export const sshCertificateAuthorityDALFactory = (db: TDbClient) => {
  const orm = ormify(db, TableName.SshCertificateAuthority);
  
  return {
    ...orm,
    
    findByProjectId: async (projectId: string) => {
      return await orm.find({ projectId });
    },
    
    findActiveByProjectId: async (projectId: string) => {
      return await orm.find({ projectId, status: "active" });
    }
  };
};