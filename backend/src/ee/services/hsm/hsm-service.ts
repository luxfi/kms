// HSM service - enterprise feature with Zymbit and Google Cloud KMS support

import { HsmModule } from './hsm-types';
import { createZymbitHSM, createGoogleCloudKMS, detectHsmProvider, HsmProviderType } from './providers';

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

/**
 * Create HSM module based on provider type
 */
function createHsmModule(provider?: HsmProviderType): HsmModule | null {
  const envProvider = process.env.HSM_PROVIDER as HsmProviderType;
  const libPath = process.env.HSM_LIB_PATH || '';

  // Determine provider
  let selectedProvider = provider || envProvider;
  if (!selectedProvider || selectedProvider === 'auto') {
    selectedProvider = detectHsmProvider(libPath);
  }

  // Create provider-specific module
  switch (selectedProvider) {
    case 'zymbit':
      return createZymbitHSM();
    case 'google-cloud':
      return createGoogleCloudKMS();
    case 'auto':
      // No HSM configured
      return null;
    default:
      throw new Error(`Unsupported HSM provider: ${selectedProvider}`);
  }
}

export const hsmServiceFactory = (params?: any): THsmServiceFactory => {
  let hsmModule: HsmModule | null = null;
  let initialized = false;

  return {
    createModule: async (moduleId: string) => {
      // Create HSM module with specified ID
      hsmModule = createHsmModule();
      if (hsmModule) {
        hsmModule.initialize();
        initialized = true;
      }
    },

    getModules: async () => {
      // Return list of available HSM modules
      if (!hsmModule) {
        return [];
      }
      return [
        {
          id: 'hsm-primary',
          provider: process.env.HSM_PROVIDER || 'auto',
          active: initialized
        }
      ];
    },

    initialize: async () => {
      // Initialize HSM service
      if (process.env.HSM_ENABLED === 'true' && !hsmModule) {
        hsmModule = createHsmModule();
        if (hsmModule) {
          hsmModule.initialize();
          initialized = true;
          console.log('HSM service initialized successfully');
        }
      }
    },

    isEnabled: () => {
      // Check if HSM is enabled via environment
      return process.env.HSM_ENABLED === 'true';
    },

    startService: async () => {
      // Start HSM service
      if (!initialized && process.env.HSM_ENABLED === 'true') {
        hsmModule = createHsmModule();
        if (hsmModule) {
          hsmModule.initialize();
          initialized = true;
        }
      }
    },

    isActive: () => {
      // Check if HSM is active
      return initialized && hsmModule !== null;
    },

    encrypt: async (data: Buffer) => {
      if (!initialized || !hsmModule) {
        throw new Error('HSM not initialized. Enable with HSM_ENABLED=true');
      }
      // Use HSM for encryption
      return (hsmModule as any).encrypt(data);
    },

    decrypt: async (data: Buffer) => {
      if (!initialized || !hsmModule) {
        throw new Error('HSM not initialized. Enable with HSM_ENABLED=true');
      }
      // Use HSM for decryption
      return (hsmModule as any).decrypt(data);
    }
  };
};