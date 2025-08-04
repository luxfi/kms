// Stub SSH CA functions - enterprise feature removed

export const createSshCaHelper = () => {
  // Stub implementation
  return {
    generateKeyPair: () => ({ publicKey: "", privateKey: "" }),
    signCertificate: () => "",
    verifyCertificate: () => true
  };
};