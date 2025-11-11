// static/js/auth.js
async function getValidToken() {
  let token = localStorage.getItem("access_token");
  const refresh = localStorage.getItem("refresh_token");

  if (!token && !refresh) return null;

  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    const exp = payload.exp * 1000;
    const now = Date.now();

    if (now > exp && refresh) {
      // Token expired, try refresh
      const res = await fetch('/api/refresh', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${refresh}` }
      });
      if (res.ok) {
        const data = await res.json();
        localStorage.setItem("access_token", data.access_token);
        token = data.access_token;
      } else {
        localStorage.removeItem("access_token");
        localStorage.removeItem("refresh_token");
        return null;
      }
    }
  } catch (e) {
    console.error("Token check failed", e);
    return null;
  }

  return token;
}
