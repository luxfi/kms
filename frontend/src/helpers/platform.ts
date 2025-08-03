export const isKMSCloud = () =>
  window.location.origin.includes("https://kms.lux.network") ||
  window.location.origin.includes("https://us.lux.network") ||
  window.location.origin.includes("https://eu.lux.network") ||
  window.location.origin.includes("https://gamma.lux.network");
