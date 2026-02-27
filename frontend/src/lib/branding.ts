/**
 * Domain-based white-label branding for KMS.
 * Detects the current domain and returns the appropriate branding config.
 */

export interface BrandConfig {
  name: string;
  idName: string;
  logo: string;
  navLogo: string;
  favicon: string;
  supportEmail: string;
  docsUrl: string;
}

const BRANDS: Record<string, BrandConfig> = {
  hanzo: {
    name: "Hanzo KMS",
    idName: "Hanzo ID",
    logo: "/images/brands/hanzo-logo.svg",
    navLogo: "/images/brands/hanzo-logo.svg",
    favicon: "/kms.ico",
    supportEmail: "support@hanzo.ai",
    docsUrl: "https://hanzo.ai/docs"
  },
  lux: {
    name: "Lux KMS",
    idName: "Lux ID",
    logo: "/images/brands/lux-logo.svg",
    navLogo: "/images/brands/lux-logo.svg",
    favicon: "/lux.ico",
    supportEmail: "support@lux.network",
    docsUrl: "https://lux.network/docs"
  },
  zoo: {
    name: "Zoo KMS",
    idName: "Zoo ID",
    logo: "/images/brands/zoo-logo.svg",
    navLogo: "/images/brands/zoo-logo.svg",
    favicon: "/kms.ico",
    supportEmail: "support@zoo.network",
    docsUrl: "https://zoo.network/docs"
  },
  pars: {
    name: "Pars KMS",
    idName: "Pars ID",
    logo: "/images/brands/pars-logo.svg",
    navLogo: "/images/brands/pars-logo.svg",
    favicon: "/kms.ico",
    supportEmail: "support@pars.network",
    docsUrl: "https://pars.network/docs"
  }
};

function detectBrand(): string {
  const hostname = typeof window !== "undefined" ? window.location.hostname : "";
  if (hostname.includes("lux")) return "lux";
  if (hostname.includes("zoo")) return "zoo";
  if (hostname.includes("pars")) return "pars";
  return "hanzo";
}

let cachedBrand: BrandConfig | null = null;

export function getBrand(): BrandConfig {
  if (!cachedBrand) {
    cachedBrand = BRANDS[detectBrand()];
  }
  return cachedBrand;
}
