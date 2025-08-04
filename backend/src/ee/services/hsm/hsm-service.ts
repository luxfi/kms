// HSM service - enterprise feature removed

export type THsmServiceFactory = {
  createModule: (moduleId: string) => Promise<void>;
  getModules: () => Promise<any[]>;
  initialize: () => Promise<void>;
  isEnabled: () => boolean;
  startService: () => Promise<void>;
  isActive: () => boolean;
  encrypt: (data: Buffer) => Promise<Buffer>;
  decrypt: (data: Buffer) => Promise<Buffer>;
};

export const hsmServiceFactory = (params?: any): THsmServiceFactory => {
  return {
    createModule: async (moduleId: string) => {
      // Stub implementation
      return;
    },
    
    getModules: async () => {
      // Stub - return empty array
      return [];
    },
    
    initialize: async () => {
      // Stub - do nothing
      return;
    },
    
    isEnabled: () => {
      // HSM is disabled in community edition
      return false;
    },
    
    startService: async () => {
      // Stub - do nothing
      return;
    },
    
    isActive: () => {
      // HSM is not active in community edition
      return false;
    },
    
    encrypt: async (data: Buffer) => {
      throw new Error("HSM encryption not available in community edition");
    },
    
    decrypt: async (data: Buffer) => {
      throw new Error("HSM decryption not available in community edition");
    }
  };
};