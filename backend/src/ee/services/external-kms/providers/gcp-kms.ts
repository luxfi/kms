// Stub GCP KMS provider - enterprise feature removed
import { TExternalKmsProviderFns } from "./model";

export const GcpKmsProviderFactory = (config: any): TExternalKmsProviderFns => {
  return {
    encrypt: async (data: Buffer): Promise<{ encryptedBlob: Buffer }> => {
      // Stub - just return the data as-is
      return { encryptedBlob: data };
    },
    
    decrypt: async (data: Buffer): Promise<{ data: Buffer }> => {
      // Stub - just return the data as-is
      return { data };
    },
    
    generateDataKey: async (): Promise<{ plaintext: Buffer; ciphertext: Buffer }> => {
      // Stub - return dummy data
      return {
        plaintext: Buffer.from("dummy-plaintext"),
        ciphertext: Buffer.from("dummy-ciphertext")
      };
    },
    
    cleanup: async (): Promise<void> => {
      // Stub - do nothing
    }
  };
};