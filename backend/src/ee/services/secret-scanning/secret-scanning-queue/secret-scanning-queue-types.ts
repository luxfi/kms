// Secret scanning queue types - enterprise feature stub

export interface TScanFullRepositoryMessage {
  installationId: string;
  repository: {
    id: string;
    name: string;
    fullName: string;
  };
}

export interface TScanPushEventMessage {
  installationId: string;
  repository: {
    id: string;
    name: string;
    fullName: string;
  };
  commits: Array<{
    id: string;
    message: string;
    author: {
      name: string;
      email: string;
    };
  }>;
}

export type TSecretScanningQueueMessage = TScanFullRepositoryMessage | TScanPushEventMessage;

export type TScanFullRepoEventPayload = TScanFullRepositoryMessage;
export type TScanPushEventPayload = TScanPushEventMessage;