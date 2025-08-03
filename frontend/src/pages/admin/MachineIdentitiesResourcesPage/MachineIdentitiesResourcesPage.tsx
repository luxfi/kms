import { Helmet } from "react-helmet";
import { useTranslation } from "react-i18next";

import { PageHeader } from "@app/components/v2";

import { MachineIdentitiesTable } from "./components";

export const MachineIdentitiesResourcesPage = () => {
  const { t } = useTranslation();

  return (
    <div className="h-full bg-bunker-800">
      <Helmet>
        <title>{t("common.head-title", { title: "Admin" })}</title>
      </Helmet>
      <div className="container mx-auto flex flex-col justify-between bg-bunker-800 text-white">
        <div className="mx-auto mb-6 w-full max-w-7xl">
          <PageHeader
            title="Machine Identities"
            description="Manage all machine identities within your KMS instance."
          />
          <MachineIdentitiesTable />
        </div>
      </div>
    </div>
  );
};
