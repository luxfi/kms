import { Tab, TabList, TabPanel, Tabs } from "@app/components/v2";
import { OrgPermissionBillingActions, OrgPermissionSubjects } from "@app/context";
import { isKMSCloud } from "@app/helpers/platform";
import { withPermission } from "@app/hoc";

import { BillingCloudTab } from "../BillingCloudTab";
import { BillingDetailsTab } from "../BillingDetailsTab";
import { BillingReceiptsTab } from "../BillingReceiptsTab";
import { BillingSelfHostedTab } from "../BillingSelfHostedTab";

const tabs = [
  { name: "KMS Cloud", key: "tab-kms-cloud" },
  { name: "KMS Self-Hosted", key: "tab-kms-self-hosted" },
  { name: "Receipts", key: "tab-receipts" },
  { name: "Billing details", key: "tab-billing-details" }
];

export const BillingTabGroup = withPermission(
  () => {
    const tabsFiltered = isKMSCloud()
      ? tabs
      : [{ name: "KMS Self-Hosted", key: "tab-kms-cloud" }];

    return (
      <Tabs defaultValue={tabs[0].key}>
        <TabList>
          {tabsFiltered.map((tab) => (
            <Tab value={tab.key}>{tab.name}</Tab>
          ))}
        </TabList>
        <TabPanel value={tabs[0].key}>
          <BillingCloudTab />
        </TabPanel>
        {isKMSCloud() && (
          <>
            <TabPanel value={tabs[1].key}>
              <BillingSelfHostedTab />
            </TabPanel>
            <TabPanel value={tabs[2].key}>
              <BillingReceiptsTab />
            </TabPanel>
            <TabPanel value={tabs[3].key}>
              <BillingDetailsTab />
            </TabPanel>
          </>
        )}
      </Tabs>
    );
  },
  { action: OrgPermissionBillingActions.Read, subject: OrgPermissionSubjects.Billing }
);
