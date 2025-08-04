// HSM functions - enterprise feature removed

export const generateRandomUuid = (): string => {
  return crypto.randomUUID();
};

export const initializeHsmModule = (envConfig: any) => {
  // Stub - return a dummy HSM module
  return {
    initialize: () => {
      // Do nothing in community edition
    },
    getModule: () => {
      // Return a dummy module
      return {
        isInitialized: () => false,
        encrypt: async (data: Buffer) => data,
        decrypt: async (data: Buffer) => data,
        sign: async (data: Buffer) => Buffer.from('dummy-signature'),
        verify: async (data: Buffer, signature: Buffer) => true
      };
    }
  };
};

export const encryptWithHsm = async (data: Buffer): Promise<Buffer> => {
  // Stub - just return the data as-is
  return data;
};

export const decryptWithHsm = async (data: Buffer): Promise<Buffer> => {
  // Stub - just return the data as-is
  return data;
};

export const signWithHsm = async (data: Buffer): Promise<Buffer> => {
  // Stub - return a dummy signature
  return Buffer.from('dummy-signature');
};

export const verifyWithHsm = async (data: Buffer, signature: Buffer): Promise<boolean> => {
  // Stub - always return true
  return true;
};

export const generateKeyWithHsm = async (): Promise<{ publicKey: Buffer; privateKey: Buffer }> => {
  // Stub - return dummy keys
  return {
    publicKey: Buffer.from('dummy-public-key'),
    privateKey: Buffer.from('dummy-private-key')
  };
};