// static/js/auth.js

// Get a valid (non-expired) access token from localStorage
// Returns: string token or null
async function getValidToken() {
  let access = localStorage.getItem("access_token");
  const refresh = localStorage.getItem("refresh_token");

  // No tokens at all
  if (!access && !refresh) {
    return null;
  }

  // We have a refresh but no access token -> state is broken, clear everything
  if (!access && refresh) {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    return null;
  }

  try {
    // Basic sanity check
    const parts = access.split(".");
    if (parts.length !== 3) {
      throw new Error("Invalid JWT format");
    }

    const payloadJson = atob(parts[1]);
    const payload = JSON.parse(payloadJson);

    // exp is in seconds -> convert to ms
    const expMs = (payload.exp || 0) * 1000;
    const nowMs = Date.now();

    // Token expired
    if (!expMs || nowMs >= expMs) {
      console.warn("Access token expired, clearing storage.");
      localStorage.removeItem("access_token");
      localStorage.removeItem("refresh_token");
      return null;
    }

    // Still good
    return access;
  } catch (err) {
    console.error("Failed to inspect token", err);
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    return null;
  }
}
