import { TDbClient } from "@app/db";
import { TableName } from "@app/db/schemas";
import { ormify } from "@app/lib/knex";

export type TSshCertificateAuthoritySecretDALFactory = ReturnType<typeof sshCertificateAuthoritySecretDALFactory>;

export const sshCertificateAuthoritySecretDALFactory = (db: TDbClient) => {
  const orm = ormify(db, TableName.SshCertificateAuthoritySecret);
  
  return {
    ...orm,
    
    findByCaId: async (sshCaId: string) => {
      return await orm.find({ sshCaId });
    }
  };
};