// HSM Provider exports
// Central export point for all HSM provider implementations

export { ZymbitHSM, ZymbitConfig, ZymbitDeviceInfo, createZymbitHSM } from './zymbit';
export { GoogleCloudKMS, GoogleCloudKMSConfig, createGoogleCloudKMS } from './google-cloud-kms';
export {
  AWSCloudHSM,
  AWSCloudHSMConfig,
  AWSCloudHSMClusterInfo,
  AWSCloudHSMHealthStatus,
  createAWSCloudHSM
} from './aws-cloudhsm';

// Type for provider detection
export type HsmProviderType = 'zymbit' | 'thales' | 'aws' | 'fortanix' | 'google-cloud' | 'auto';

/**
 * Auto-detect HSM provider based on library path or environment
 */
export function detectHsmProvider(libPath: string): HsmProviderType {
  const normalizedPath = libPath.toLowerCase();

  // Check environment variables for Google Cloud
  if (process.env.GOOGLE_CLOUD_PROJECT_ID || process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    return 'google-cloud';
  }

  if (normalizedPath.includes('zymbit') || normalizedPath.includes('zk_pkcs11')) {
    return 'zymbit';
  }

  if (normalizedPath.includes('cloudhsm')) {
    return 'aws';
  }

  if (normalizedPath.includes('luna') || normalizedPath.includes('thales')) {
    return 'thales';
  }

  if (normalizedPath.includes('fortanix')) {
    return 'fortanix';
  }

  return 'auto';
}
