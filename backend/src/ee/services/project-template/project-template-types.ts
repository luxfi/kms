// Minimal project template types - enterprise feature removed
import { ProjectType, TProjectEnvironments } from "@app/db/schemas";

export type TProjectTemplateEnvironment = Pick<TProjectEnvironments, "name" | "slug" | "position">;

export type TProjectTemplateRole = {
  slug: string;
  name: string;
  permissions: any[]; // Simplified permissions
};

export type TCreateProjectTemplateDTO = {
  name: string;
  type: ProjectType;
  description?: string;
  roles: TProjectTemplateRole[];
  environments?: TProjectTemplateEnvironment[] | null;
};

export type TUpdateProjectTemplateDTO = Partial<TCreateProjectTemplateDTO>;

export enum KmsProjectTemplate {
  Default = "default"
}

// Stub for the template service factory
export type TProjectTemplateServiceFactory = {
  // Minimal implementation - returns empty templates
  listProjectTemplatesByOrg: () => Promise<any[]>;
  createProjectTemplate: () => Promise<any>;
  updateProjectTemplate: () => Promise<any>;
  deleteProjectTemplate: () => Promise<void>;
  applyTemplate: () => Promise<void>;
};