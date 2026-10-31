/* 前端仅负责展示与交互。所有授权判断均在服务端完成。
   所有动态内容使用 textContent / DOM API 渲染，不使用 innerHTML 拼接用户数据。 */
"use strict";

const state = { user: null, csrf: null };
const $ = (sel) => document.querySelector(sel);
const root = $("#root");

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") node.className = v;
    else if (k === "on") for (const [ev, fn] of Object.entries(v)) node.addEventListener(ev, fn);
    else if (k in node) node[k] = v;
    else node.setAttribute(k, v);
  }
  for (const c of [].concat(children)) node.append(c);
  return node;
}

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (t.hidden = true), 2800);
}

async function api(method, path, { body, form, json = true } = {}) {
  const headers = {};
  if (state.csrf && method !== "GET") headers["X-CSRF-Token"] = state.csrf;
  let payload;
  if (form) payload = form;
  else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  const res = await fetch(path, { method, headers, body: payload, credentials: "same-origin" });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = data?.error?.message || "请求失败";
    const e = new Error(msg);
    e.code = data?.error?.code;
    e.status = res.status;
    throw e;
  }
  return data;
}

// ---------- 验证码 ----------
async function captchaBlock() {
  const wrap = el("div", { class: "captcha" });
  const img = el("img", { alt: "验证码", width: 200, height: 70 });
  const refresh = el("button", { type: "button", textContent: "刷新" });
  const state2 = { id: null };
  async function load() {
    const data = await api("GET", "/api/captcha");
    state2.id = data.captchaId;
    img.src = data.image;
  }
  refresh.addEventListener("click", () => load().catch((e) => toast(e.message)));
  wrap.append(img, refresh);
  await load();
  return { node: wrap, get: () => ({ captchaId: state2.id }), reload: load };
}

// ---------- 页面 ----------
function renderAuth(mode = "login") {
  root.replaceChildren();
  const err = el("p", { class: "error" });
  const tabs = el("div", { class: "row" }, [
    el("button", { type: "button", textContent: "登录", class: mode === "login" ? "primary" : "", on: { click: () => renderAuth("login") } }),
    el("button", { type: "button", textContent: "注册", class: mode === "register" ? "primary" : "", on: { click: () => renderAuth("register") } }),
  ]);
  const email = el("input", { type: "email", autocomplete: "email", required: true, maxLength: 254 });
  const password = el("input", { type: "password", autocomplete: mode === "login" ? "current-password" : "new-password", required: true, maxLength: 128 });
  const answer = el("input", { type: "text", autocomplete: "off", maxLength: 8, placeholder: "图中字符", required: true });
  const submit = el("button", { type: "submit", class: "primary", textContent: mode === "login" ? "登录" : "注册" });

  const form = el("form", { class: "card" }, []);
  let captcha;
  (async () => {
    captcha = await captchaBlock();
    form.append(captcha.node);
  })().catch((e) => (err.textContent = e.message));

  form.append(
    el("label", { textContent: "邮箱" }), email,
    el("label", { textContent: "密码" }), password,
    el("label", { textContent: "验证码" }), answer,
    el("div", { class: "row" }, [submit]),
    err,
  );

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    err.textContent = "";
    submit.disabled = true;
    try {
      const cap = captcha.get();
      const payload = { email: email.value, password: password.value, captchaId: cap.captchaId, captchaAnswer: answer.value };
      if (mode === "register") {
        const r = await api("POST", "/api/auth/register", { body: payload });
        if (r.devVerificationToken) toast("开发模式：验证令牌已返回");
        renderAuth("login");
        toast(r.message);
      } else {
        const r = await api("POST", "/api/auth/login", { body: payload });
        state.user = r.user;
        state.csrf = r.csrfToken;
        await enterApp();
      }
    } catch (e) {
      err.textContent = e.message;
      answer.value = "";
      captcha?.reload().catch(() => {});
    } finally {
      submit.disabled = false;
    }
  });

  root.append(tabs, form);
}

async function renderVerify(token) {
  root.replaceChildren(el("div", { class: "card" }, [el("h2", { textContent: "邮箱验证" }), el("p", { id: "vmsg", textContent: "验证中…" })]));
  try {
    const r = await api("POST", "/api/auth/verify-email", { body: { token } });
    $("#vmsg").textContent = r.message;
  } catch (e) {
    $("#vmsg").textContent = e.message;
  }
}

async function enterApp() {
  $("#nav").hidden = false;
  $("#nav-admin").hidden = !state.user.isSuperAdmin;
  renderSites();
}

async function renderSites() {
  root.replaceChildren();
  const list = el("div", { class: "card" }, [el("p", { class: "muted", textContent: "加载中…" })]);
  const nameInput = el("input", { placeholder: "站点名称（1-80 字）", maxLength: 80 });
  const create = el("button", { class: "primary", type: "button", textContent: "创建站点" });
  const err = el("p", { class: "error" });
  create.addEventListener("click", async () => {
    err.textContent = "";
    try {
      await api("POST", "/api/sites", { body: { name: nameInput.value } });
      toast("站点已创建");
      renderSites();
    } catch (e) {
      err.textContent = e.message;
    }
  });
  root.append(
    el("div", { class: "card" }, [el("h2", { textContent: "新建站点" }), el("div", { class: "row" }, [nameInput, create]), err]),
    list,
  );

  try {
    const { sites } = await api("GET", "/api/sites");
    list.replaceChildren(el("h2", { textContent: "我的站点" }));
    if (sites.length === 0) list.append(el("p", { class: "muted", textContent: "还没有站点" }));
    for (const s of sites) list.append(siteRow(s));
  } catch (e) {
    list.replaceChildren(el("p", { class: "error", textContent: e.message }));
  }
}

function siteRow(s) {
  const link = el("a", { href: s.url, target: "_blank", rel: "noopener noreferrer", textContent: s.url });
  const upload = el("button", { type: "button", textContent: "上传文件", on: { click: () => renderUpload(s) } });
  const del = el("button", {
    type: "button", class: "danger", textContent: "删除",
    on: {
      click: async () => {
        if (!confirm(`确定删除站点“${s.name}”？`)) return;
        try { await api("DELETE", `/api/sites/${s.id}`); renderSites(); } catch (e) { toast(e.message); }
      },
    },
  });
  return el("div", { class: "card" }, [
    el("strong", { textContent: s.name }),
    el("div", { class: "muted", textContent: `${s.fileCount} 个文件 · ${s.totalBytes} 字节` }),
    el("div", {}, [link]),
    el("div", { class: "row" }, [upload, del]),
  ]);
}

async function renderUpload(site) {
  root.replaceChildren();
  const picker = el("input", { type: "file", multiple: true, accept: ".html,.htm,.css,.js,.mjs,.json,.txt,.md,.png,.jpg,.jpeg,.gif,.webp,.svg,.ico,.woff,.woff2,.ttf" });
  const progress = el("div", { class: "progress" }, [el("div")]);
  const msg = el("p", { class: "muted" });
  const err = el("p", { class: "error" });
  const answer = el("input", { placeholder: "验证码", maxLength: 8, autocomplete: "off" });
  const submit = el("button", { class: "primary", type: "button", textContent: "开始上传" });
  const cap = await captchaBlock().catch((e) => { err.textContent = e.message; return null; });

  submit.addEventListener("click", async () => {
    err.textContent = "";
    if (!picker.files?.length) return (err.textContent = "请选择文件");
    if (!cap) return (err.textContent = "验证码加载失败");
    const form = new FormData();
    // 文件名即相对路径（前端可用 webkitRelativePath 等方式扩展）
    for (const f of picker.files) form.append("files", f, f.name);
    form.append("captchaId", cap.get().captchaId);
    form.append("captchaAnswer", answer.value);
    submit.disabled = true;
    try {
      await uploadWithProgress(`/api/sites/${site.id}/upload`, form, (pct) => {
        progress.firstChild.style.width = `${pct}%`;
      });
      msg.textContent = `上传成功：${site.url}`;
      toast("上传成功");
      renderSites();
    } catch (e) {
      err.textContent = e.message;
      answer.value = "";
      cap.reload().catch(() => {});
    } finally {
      submit.disabled = false;
    }
  });

  root.append(
    el("div", { class: "card" }, [
      el("h2", { textContent: `上传到：${site.name}` }),
      el("p", { class: "muted", textContent: "仅允许静态文件（HTML/CSS/JS/图片/字体等），禁止可执行或服务端文件。" }),
      picker,
      el("label", { textContent: "验证码" }),
      cap ? cap.node : el("p", { class: "error", textContent: "验证码加载失败" }),
      answer,
      el("div", { class: "row" }, [submit]),
      progress, msg, err,
    ]),
  );
}

// 使用 XHR 以获得上传进度；CSRF 头与 Cookie 与其它请求一致
function uploadWithProgress(path, form, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", path);
    xhr.withCredentials = true;
    if (state.csrf) xhr.setRequestHeader("X-CSRF-Token", state.csrf);
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(Math.round((e.loaded / e.total) * 100));
    xhr.onload = () => {
      let data = {};
      try { data = JSON.parse(xhr.responseText); } catch { /* ignore */ }
      if (xhr.status >= 200 && xhr.status < 300) resolve(data);
      else reject(new Error(data?.error?.message || "上传失败"));
    };
    xhr.onerror = () => reject(new Error("网络错误"));
    xhr.send(form);
  });
}

async function renderAdmin() {
  root.replaceChildren();
  const usersCard = el("div", { class: "card" }, [el("h2", { textContent: "用户" })]);
  const sitesCard = el("div", { class: "card" }, [el("h2", { textContent: "站点" })]);
  const logsCard = el("div", { class: "card" }, [el("h2", { textContent: "审计日志" })]);
  root.append(usersCard, sitesCard, logsCard);

  try {
    const { users } = await api("GET", "/api/admin/users?limit=100");
    const t = el("table", {}, [el("tr", {}, ["邮箱", "状态", "已验证", "站点数", "操作"].map((h) => el("th", { textContent: h })))]);
    for (const u of users) {
      const toggle = u.protected
        ? el("span", { class: "muted", textContent: "环境变量超级用户" })
        : el("button", {
            type: "button", textContent: u.status === "active" ? "禁用" : "启用",
            on: { click: async () => { try { await api("POST", `/api/admin/users/${u.id}/${u.status === "active" ? "disable" : "enable"}`); renderAdmin(); } catch (e) { toast(e.message); } } },
          });
      t.append(el("tr", {}, [
        el("td", { textContent: u.email }),
        el("td", { textContent: u.status }),
        el("td", { textContent: u.emailVerified ? "是" : "否" }),
        el("td", { textContent: String(u.siteCount) }),
        el("td", {}, [toggle]),
      ]));
    }
    usersCard.append(t);
  } catch (e) { usersCard.append(el("p", { class: "error", textContent: e.message })); }

  try {
    const { sites } = await api("GET", "/api/admin/sites?limit=100");
    const t = el("table", {}, [el("tr", {}, ["站点", "所有者", "文件数", "操作"].map((h) => el("th", { textContent: h })))]);
    for (const s of sites) {
      t.append(el("tr", {}, [
        el("td", { textContent: s.name }),
        el("td", { textContent: s.ownerEmail }),
        el("td", { textContent: String(s.fileCount) }),
        el("td", {}, [el("button", {
          type: "button", class: "danger", textContent: "删除",
          on: { click: async () => { if (!confirm("删除该站点？")) return; try { await api("DELETE", `/api/admin/sites/${s.id}`); renderAdmin(); } catch (e) { toast(e.message); } } },
        })]),
      ]));
    }
    sitesCard.append(t);
  } catch (e) { sitesCard.append(el("p", { class: "error", textContent: e.message })); }

  try {
    const { logs } = await api("GET", "/api/admin/audit?limit=100");
    const t = el("table", {}, [el("tr", {}, ["时间", "动作", "目标", "结果"].map((h) => el("th", { textContent: h })))]);
    for (const l of logs) {
      t.append(el("tr", {}, [
        el("td", { textContent: new Date(l.createdAt * 1000).toLocaleString() }),
        el("td", { textContent: l.action }),
        el("td", { textContent: l.target ?? "" }),
        el("td", { textContent: l.result }),
      ]));
    }
    logsCard.append(t);
  } catch (e) { logsCard.append(el("p", { class: "error", textContent: e.message })); }
}

function renderPassword() {
  root.replaceChildren();
  const cur = el("input", { type: "password", autocomplete: "current-password" });
  const nw = el("input", { type: "password", autocomplete: "new-password" });
  const err = el("p", { class: "error" });
  const btn = el("button", { class: "primary", type: "button", textContent: "保存" });
  btn.addEventListener("click", async () => {
    err.textContent = "";
    try {
      const r = await api("POST", "/api/auth/change-password", { body: { currentPassword: cur.value, newPassword: nw.value } });
      state.csrf = r.csrfToken;
      toast("密码已更新");
      cur.value = ""; nw.value = "";
    } catch (e) { err.textContent = e.message; }
  });
  root.append(el("div", { class: "card" }, [
    el("h2", { textContent: "修改密码" }),
    el("label", { textContent: "当前密码" }), cur,
    el("label", { textContent: "新密码（至少 10 位，含大小写与数字）" }), nw,
    el("div", { class: "row" }, [btn]), err,
  ]));
}

// ---------- 启动 ----------
$("#nav-sites").addEventListener("click", () => renderSites());
$("#nav-admin").addEventListener("click", () => renderAdmin());
$("#nav-password").addEventListener("click", () => renderPassword());
$("#nav-logout").addEventListener("click", async () => {
  await api("POST", "/api/auth/logout").catch(() => {});
  state.user = null; state.csrf = null;
  $("#nav").hidden = true;
  renderAuth("login");
});

(async function boot() {
  const params = new URLSearchParams(location.search);
  if (location.pathname === "/verify-email" && params.get("token")) {
    return renderVerify(params.get("token"));
  }
  try {
    const me = await api("GET", "/api/auth/me");
    state.user = me.user;
    state.csrf = me.csrfToken;
    await enterApp();
  } catch {
    renderAuth("login");
  }
})();
