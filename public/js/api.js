// public/js/api.js
// Small fetch wrapper shared by all dashboard pages.

const Api = (() => {
  function token() {
    return localStorage.getItem("uhrp_token");
  }
  function setSession(token, user) {
    localStorage.setItem("uhrp_token", token);
    localStorage.setItem("uhrp_user", JSON.stringify(user));
  }
  function clearSession() {
    localStorage.removeItem("uhrp_token");
    localStorage.removeItem("uhrp_user");
  }
  function currentUser() {
    const raw = localStorage.getItem("uhrp_user");
    return raw ? JSON.parse(raw) : null;
  }

  async function request(method, url, body) {
    const headers = { "Content-Type": "application/json" };
    const t = token();
    if (t) headers.Authorization = `Bearer ${t}`;

    const res = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    let data = null;
    try {
      data = await res.json();
    } catch (_) {
      /* no body */
    }

    if (!res.ok) {
      const err = new Error((data && data.error) || `Request failed (${res.status})`);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  return {
    get: (url) => request("GET", url),
    post: (url, body) => request("POST", url, body),
    put: (url, body) => request("PUT", url, body),
    setSession,
    clearSession,
    currentUser,
    isLoggedIn: () => !!token(),
  };
})();

function requireRoleOrRedirect(role) {
  const user = Api.currentUser();
  if (!Api.isLoggedIn() || !user || user.role !== role) {
    window.location.href = "/index.html";
    return null;
  }
  return user;
}

function showMsg(el, text, type = "error") {
  el.textContent = text;
  el.className = `msg ${type}`;
  el.classList.remove("hidden");
}
