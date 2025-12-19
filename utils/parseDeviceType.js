const parseDeviceType = (userAgent) => {
  const ua = userAgent.toLowerCase();

  if (!ua) return "unknown";

  // Tablet
  if (
    ua.includes("ipad") ||
    ua.includes("tablet") ||
    (ua.includes("android") && !ua.includes("mobile"))
  ) {
    return "tablet";
  }

  // Mobile
  if (
    ua.includes("mobi") ||
    ua.includes("iphone") ||
    ua.includes("ipod") ||
    ua.includes("android") ||
    ua.includes("blackberry") ||
    ua.includes("phone")
  ) {
    return "mobile";
  }

  // Desktop
  if (
    ua.includes("windows") ||
    ua.includes("macintosh") ||
    ua.includes("linux") ||
    ua.includes("x11")
  ) {
    return "desktop";
  }

  return "unknown";
};

module.exports = parseDeviceType;
