import { OrgAlertBanner } from "../OrgAlertBanner";

export const RedisBanner = () => {
  return (
    <OrgAlertBanner
      text="Attention: Updated versions of KMS now require Redis for full functionality."
      link="https://lux.network/docs/self-hosting/configuration/requirements#redis"
    />
  );
};
