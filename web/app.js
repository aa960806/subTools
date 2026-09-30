"use strict";
const $ = (s) => document.querySelector(s),
  $$ = (s) => Array.from(document.querySelectorAll(s));
const esc = (s) =>
  String(s ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
let csrf = "",
  page = "auth",
  configs = {},
  countries = [],
  current = null,
  active = null,
  taskByPage = {},
  drafts = {},
  selected = new Set(),
  groups = [],
  proxies = [],
  sources = [],
  quotes = [],
  timer = null,
  frameUrl = null,
  polling = false,
  settingsReady = false;
const labels = {
  auth: "批量授权",
  phone: "手机接码",
  convert: "格式转换",
  pool: "推送到池",
  history: "任务历史",
  inspect: "只读巡检",
};
const states = {
  success: "成功",
  created: "已创建",
  updated: "已更新",
  failed: "失败",
  ready: "待处理",
  not_processed: "未处理",
  cancelled: "已停止",
  needs_interaction: "需要操作",
  phone_required: "待补手机",
  refresh_failed: "刷新失败",
  refresh_unknown: "刷新待核对",
  refreshing: "刷新中",
  pushing: "推送中",
  relogin: "重新登录",
  identity: "身份待核对",
  uncertain: "写入待核对",
  deferred: "已暂缓",
  attention: "需关注",
  network: "网络异常",
  server: "服务异常",
  rate_limited: "已限流",
  circuit_open: "已熔断",
  phone_fraud: "风控拒绝",
};
const good = (s) => ["success", "created", "updated"].includes(s),
  pending = (s) =>
    [
      "ready",
      "not_processed",
      "deferred",
      "pushing",
      "refreshing",
      "relogin",
    ].includes(s);
async function api(path, method = "GET", data, blob = false) {
  const options = {
    method,
    headers: { "X-CSRF-Token": csrf },
    cache: "no-store",
  };
  if (data !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(data);
  }
  const r = await fetch("/api" + path, options);
  if (r.status === 401 && path != "/login") {
    showLogin();
    throw Error("请重新登录");
  }
  if (!r.ok) {
    let e;
    try {
      e = await r.json();
    } catch {
      e = { error: `请求失败（HTTP ${r.status}）` };
    }
    throw Error(e.error || "操作失败");
  }
  return blob ? r.blob() : r.status === 204 ? null : r.json();
}
function notify(message, error = false) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.toggle("error", error);
  node.hidden = false;
  clearTimeout(node._timeout);
  node._timeout = setTimeout(() => (node.hidden = true), 7000);
}
const act = (fn) => async (event) => {
  try {
    await fn(event);
  } catch (e) {
    notify(e.message, true);
  }
};
function on(id, fn) {
  $(id).addEventListener("click", act(fn));
}
function showLogin() {
  settingsReady = false;
  configs = {};
  drafts = {};
  taskByPage = {};
  current = null;
  selected.clear();
  $("#account-input").value = "";
  $("#convert-input").value = "";
  $("#convert-preview").textContent = "结果将在此显示";
  $("#settings-body").replaceChildren();
  $("#browser-text").value = "";
  $("#browser-frame").removeAttribute("src");
  if (frameUrl) {
    URL.revokeObjectURL(frameUrl);
    frameUrl = null;
  }
  $("#browser-dialog").close();
  $("#login").hidden = false;
  $("#app").hidden = true;
  csrf = "";
  if (timer) clearInterval(timer);
}
function secret(key, label, v) {
  return `<div class="field"><label>${label}<div class="secret-field"><input data-field="${key}" type="password" value="${esc(v[key] || "")}" autocomplete="off" placeholder="${v[key + "_saved"] ? "已加密保存；留空保留" : "填写后保存"}"><button type="button" data-eye="${key}" aria-label="显示或隐藏${label}">◉</button></div></label>${v[key + "_saved"] ? `<label class="check"><input type="checkbox" data-field="clear_${key}" ${v["clear_" + key] ? "checked" : ""}>清除已保存内容</label>` : ""}</div>`;
}
function input(key, label, v, type = "text", hint = "") {
  return `<label class="field">${label}<input data-field="${key}" type="${type}" value="${esc(v[key] ?? "")}" ${type === "number" ? (key === "human_scale" ? 'min="0.1" max="10" step="0.1"' : 'min="0"') : ""}></label>${hint ? `<p class="hint">${hint}</p>` : ""}`;
}
function select(key, label, v, options) {
  return `<label class="field">${label}<select data-field="${key}">${options.map(([k, l]) => `<option value="${esc(k)}" ${String(v[key] ?? "") === String(k) ? "selected" : ""}>${esc(l)}</option>`).join("")}</select></label>`;
}
function check(key, label, v) {
  return `<label class="check"><input data-field="${key}" type="checkbox" ${v[key] ? "checked" : ""}>${label}</label>`;
}
function network(v) {
  return `<h3>网络与代理</h3>${select("network_mode", "网络模式", v, [
    ["direct", "直连"],
    ["system", "服务器系统代理"],
    ["custom", "自定义代理"],
  ])}${select("proxy_scheme", "代理协议", v, [
    ["http", "HTTP"],
    ["https", "HTTPS"],
    ["socks5", "SOCKS5"],
  ])}${secret("proxy", "代理地址", v)}<p class="hint">系统代理读取服务器配置；不读取访问网页这台电脑的代理。</p>`;
}
function running(v) {
  return `<h3>运行设置</h3>${input("timeout", "每账号处理超时（秒）", v, "number")}${check("show_browser", "显示浏览器（网页内查看与操作）", v)}${check("human_pacing", "启用步骤等待", v)}${input("human_scale", "等待时间倍数", v, "number")}`;
}
function renderSettings() {
  if (!["auth", "phone", "pool"].includes(page)) return;
  const v = configs[page];
  let html = "";
  $("#settings-title").textContent = {
    auth: "授权设置",
    phone: "接码设置",
    pool: "推池设置",
  }[page];
  if (page === "auth") html = network(v) + running(v);
  if (page === "phone") {
    html =
      network(v) +
      `<h3>SMSBower</h3>${secret("api_key", "API Key", v)}<div class="tools"><button id="sms-balance" class="ghost">查询余额</button><button id="sms-quotes" class="ghost">国家报价</button></div><p id="sms-result" class="hint"></p><h3>号码与重试</h3>${select(
        "country",
        "接码国家（拼音 A–Z）",
        v,
        countries.map((c) => [c.code, c.label]),
      )}<div class="two-cols">${input("min_price", "最低单价", v)}${input("max_price", "最高单价", v)}</div>${check("auto_price_match", "限价内自动匹配最低报价", v)}<div class="two-cols">${input("max_reuse", "单号绑定上限", v, "number")}${input("sms_timeout", "收短信超时（秒）", v, "number")}${input("auto_retry_count", "小重试次数", v, "number")}${input("country_retry_count", "大重试换国次数", v, "number")}${input("sms_poll_interval", "短信轮询（秒）", v, "number")}</div><p class="hint">每国首次尝试 + 小重试；换国按下方顺序，预算用尽熔断。</p><label>添加自定义备用国家<select id="fallback-choice">${countries.map((c) => `<option value="${c.code}">${esc(c.label)}</option>`).join("")}</select></label><button id="fallback-add" class="ghost">＋ 添加备用国家</button><div id="fallback-list"></div><h3>国家比价</h3><button id="price-catalog" class="ghost">读取各国价格与库存</button><input id="price-search" placeholder="国家名、英文、拼音或代码"><select id="price-sort"><option value="price">按价格</option><option value="stock">按库存</option><option value="name">国家 A–Z</option></select><div id="price-rows" class="quotes"></div>${running(v)}`;
  }
  if (page === "pool") {
    html = `<div class="segments"><button data-settings-tab="connection" class="selected">连接</button><button data-settings-tab="groups">分组</button><button data-settings-tab="models">模型</button></div><div data-settings-panel="connection"><h3>sub2api 后台</h3>${input("site", "站点地址", v)}${select(
      "auth_kind",
      "管理员凭据类型",
      v,
      [
        ["api_key", "管理员 API Key"],
        ["bearer", "管理员访问令牌"],
      ],
    )}${secret("credential", "管理员凭据", v)}<button id="pool-connect" class="primary">连接并加载配置</button><p id="pool-connected" class="hint"></p></div><div data-settings-panel="groups" hidden><h3>目标分组（可多选）</h3><div id="pool-groups" class="choices"></div><div class="two-cols">${input("priority", "优先级（小值优先）", v, "number")}${input("concurrency", "后台账号并发数", v, "number")}</div>${select(
      "scheduling_mode",
      "调度配置",
      v,
      [
        ["override", "使用本次优先级与并发"],
        ["preserve", "保留已有 / 输入配置"],
      ],
    )}${select("proxy_id", "后台代理（模型请求出口）", v, [["", "保留后台代理"], ["0", "直连 / 清除绑定"], ...(v.proxy_id > 0 && !proxies.some((p) => p.id === v.proxy_id) ? [[String(v.proxy_id), `已保存代理 #${v.proxy_id}（连接后核对）`]] : []), ...proxies.map((p) => [String(p.id), p.name])])}${input("load_factor", "负载系数（留空保留，0 默认）", v, "number")}<h3>登录设置</h3>${input("timeout", "每账号登录超时（秒）", v, "number")}${check("show_browser", "显示登录浏览器", v)}<p class="hint">登录网络与步骤等待复用「批量授权」设置。手机验证跳过并标记待补手机。</p></div><div data-settings-panel="models" hidden><h3>模型白名单</h3>${select(
      "model_mode",
      "模型策略",
      v,
      [
        ["preserve", "保留原模型配置"],
        ["replace", "使用保留的模型"],
        ["clear", "清除模型限制"],
      ],
    )}<div class="tools"><button id="model-sources" class="ghost">加载来源账号</button></div><select id="model-source">${sources.map((s) => `<option value="${s.id}">${esc(s.name)}</option>`).join("")}</select><button id="model-sync" class="ghost">同步上游支持模型</button><p class="hint">同步后可删除或保留；已删除的模型再次同步时保持删除。</p><input id="model-search" placeholder="搜索模型"><div id="model-rows" class="choices"></div><input id="custom-model" placeholder="自定义模型，多个用逗号分隔"><button id="model-add" class="ghost">添加模型</button></div>`;
  }
  $("#settings-body").innerHTML = html;
  settingsReady = true;
  $$("[data-eye]").forEach(
    (b) =>
      (b.onclick = () => {
        const i = $(`[data-field="${b.dataset.eye}"]`);
        i.type = i.type === "password" ? "text" : "password";
      }),
  );
  $$("[data-settings-tab]").forEach(
    (b) =>
      (b.onclick = () => {
        $$("[data-settings-tab]").forEach((x) =>
          x.classList.toggle("selected", x === b),
        );
        $$("[data-settings-panel]").forEach(
          (x) => (x.hidden = x.dataset.settingsPanel !== b.dataset.settingsTab),
        );
      }),
  );
  if (page === "phone") {
    renderFallback();
    on("#fallback-add", () => {
      const code = $("#fallback-choice").value;
      if (
        code === $("[data-field=country]").value ||
        configs.phone.fallback_countries.includes(code)
      )
        throw Error("主国家或备用国家不能重复");
      configs.phone.fallback_countries.push(code);
      renderFallback();
    });
    on("#sms-balance", async () => {
      await save();
      const r = await api("/sms/balance", "POST", {});
      $("#sms-result").textContent = "余额：" + r.balance;
    });
    on("#sms-quotes", async () => {
      await save();
      const r = await api("/sms/quotes", "POST", {});
      $("#sms-result").textContent = r.length
        ? r
            .slice(0, 5)
            .map((x) => `$${x.price} · 库存 ${x.count}`)
            .join("；")
        : "当前暂无报价";
    });
    on("#price-catalog", async () => {
      await save();
      quotes = await api("/sms/prices", "POST", {});
      renderPrices();
    });
    $("#price-search").oninput = renderPrices;
    $("#price-sort").onchange = renderPrices;
    renderPrices();
  }
  if (page === "pool") {
    renderGroups();
    renderModels();
    on("#pool-connect", async () => {
      await save();
      const data = await api("/pool/connect", "POST", {});
      groups = data.groups;
      proxies = data.proxies;
      renderSettings();
      $("#pool-connected").textContent =
        `连接成功：${groups.length} 个分组 / ${proxies.length} 个代理`;
      notify("后台连接成功");
    });
    on("#model-sources", async () => {
      await save();
      sources = await api("/pool/sources", "POST", {});
      $("#model-source").innerHTML = sources
        .map((s) => `<option value="${s.id}">${esc(s.name)}</option>`)
        .join("");
      if (!sources.length) notify("后台还没有可用来源账号，请先推送一个账号");
    });
    on("#model-sync", async () => {
      await save();
      const source = Number($("#model-source").value);
      if (!source) throw Error("请先加载来源账号");
      const r = await api("/pool/models", "POST", { source_id: source });
      for (const model of r.models)
        if (!(model in configs.pool.model_choices))
          configs.pool.model_choices[model] = true;
      renderModels();
      notify(r.notices.join("；") || `已同步 ${r.models.length} 个模型`);
    });
    on("#model-add", () => {
      const names = $("#custom-model")
        .value.split(/[,，\n;]/)
        .map((x) => x.trim())
        .filter(Boolean);
      for (const m of names) configs.pool.model_choices[m] = true;
      $("#custom-model").value = "";
      renderModels();
    });
    $("#model-search").oninput = renderModels;
  }
}
function renderFallback() {
  const v = configs.phone;
  $("#fallback-list").innerHTML = v.fallback_countries
    .map(
      (code, i) =>
        `<div class="fallback-row"><span>${i + 1}. ${esc(countries.find((c) => c.code === code)?.label || code)}</span><button data-up="${i}">↑</button><button data-remove="${i}">✕</button></div>`,
    )
    .join("");
  $$("[data-up]").forEach(
    (b) =>
      (b.onclick = () => {
        let i = Number(b.dataset.up);
        if (i)
          [v.fallback_countries[i - 1], v.fallback_countries[i]] = [
            v.fallback_countries[i],
            v.fallback_countries[i - 1],
          ];
        renderFallback();
      }),
  );
  $$("[data-remove]").forEach(
    (b) =>
      (b.onclick = () => {
        v.fallback_countries.splice(Number(b.dataset.remove), 1);
        renderFallback();
      }),
  );
}
function renderPrices() {
  const search = ($("#price-search")?.value || "").toLowerCase(),
    sort = $("#price-sort")?.value;
  const rows = quotes
    .filter((r) =>
      [r.title, r.country, countries.find((c) => c.code === r.country)?.pinyin]
        .join(" ")
        .toLowerCase()
        .includes(search),
    )
    .sort((a, b) =>
      sort === "stock"
        ? b.count - a.count
        : sort === "name"
          ? (
              countries.find((c) => c.code === a.country)?.pinyin || a.title
            ).localeCompare(
              countries.find((c) => c.code === b.country)?.pinyin || b.title,
            )
          : Number(a.price) - Number(b.price),
    );
  $("#price-rows").innerHTML = rows
    .map(
      (r) =>
        `<div class="quote-row"><span>${esc(r.title)}<br><small>库存 ${r.count}</small></span><span>$${esc(r.price)}</span><button data-primary="${r.country}" ${!r.supported ? "disabled" : ""}>主</button><button data-fallback="${r.country}" ${!r.supported ? "disabled" : ""}>备</button></div>`,
    )
    .join("");
  $$("[data-primary]").forEach(
    (b) =>
      (b.onclick = () => {
        $("[data-field=country]").value = b.dataset.primary;
        notify("已设为主国家；限价未改变");
      }),
  );
  $$("[data-fallback]").forEach(
    (b) =>
      (b.onclick = () => {
        if (
          !configs.phone.fallback_countries.includes(b.dataset.fallback) &&
          b.dataset.fallback !== $("[data-field=country]").value
        )
          configs.phone.fallback_countries.push(b.dataset.fallback);
        renderFallback();
      }),
  );
}
function renderGroups() {
  $("#pool-groups").innerHTML = groups.length
    ? groups
        .map(
          (g) =>
            `<label><input type="checkbox" data-group="${g.id}" ${configs.pool.group_ids.includes(g.id) ? "checked" : ""}>${esc(g.name)} <small>${g.id}</small></label>`,
        )
        .join("")
    : "<small>连接后台后加载分组</small>";
}
function renderModels() {
  const search = ($("#model-search")?.value || "").toLowerCase();
  $("#model-rows").innerHTML = Object.entries(configs.pool.model_choices)
    .filter(([k]) => k.toLowerCase().includes(search))
    .map(
      ([m, v]) =>
        `<label><input type="checkbox" data-model="${esc(m)}" ${v ? "checked" : ""}>${esc(m)}</label>`,
    )
    .join("");
  $$("[data-model]").forEach(
    (i) =>
      (i.onchange = () =>
        (configs.pool.model_choices[i.dataset.model] = i.checked)),
  );
}
function collect() {
  const data = {};
  $$("#settings-body [data-field]").forEach((n) => {
    let v = n.type === "checkbox" ? n.checked : n.value;
    if (n.type === "number" && v !== "") v = Number(v);
    if (["proxy_id", "load_factor"].includes(n.dataset.field))
      v = v === "" ? null : Number(v);
    data[n.dataset.field] = v;
  });
  if (page === "pool") {
    data.group_ids = groups.length
      ? $$("[data-group]:checked").map((n) => Number(n.dataset.group))
      : configs.pool.group_ids;
    data.model_choices = configs.pool.model_choices;
  }
  if (page === "phone")
    data.fallback_countries = configs.phone.fallback_countries;
  return data;
}
async function save() {
  if (!["auth", "phone", "pool"].includes(page)) return;
  const kind = page;
  const data = collect();
  configs[kind] = await api("/config/" + kind, "PUT", data);
  if (page === kind) {
    $$("[data-field]")
      .filter((n) =>
        ["proxy", "credential", "api_key"].includes(n.dataset.field),
      )
      .forEach((n) => {
        n.value = "";
        n.placeholder = "已加密保存；留空保留";
      });
    $$("[data-field^=clear_]").forEach((n) => (n.checked = false));
  }
}
async function navigate(next) {
  if (settingsReady && ["auth", "phone", "pool"].includes(page)) {
    drafts[page] = $("#account-input").value;
    Object.assign(configs[page], collect());
  }
  settingsReady = false;
  page = next;
  current = taskByPage[page] || null;
  selected.clear();
  $$("[data-page]").forEach((b) =>
    b.classList.toggle("active", b.dataset.page === page),
  );
  $("#page-title").textContent = labels[page];
  $("#breadcrumb").textContent = ["auth", "phone"].includes(page)
    ? "账号处理"
    : "数据管理";
  $("#page-description").textContent = {
    auth: "重新获取账号凭据，成功结果自动保存。",
    phone: "复用 OAuth 登录流程，自动补绑手机号。",
    convert: "多种账号格式互转，导出前清晰查看差异。",
    pool: "连接 sub2api，按身份更新凭据和分组配置。",
    history: "查阅、恢复与继续你的处理任务。",
  }[page];
  $("#work-page").hidden = !["auth", "phone", "pool"].includes(page);
  $("#convert-page").hidden = page !== "convert";
  $("#history-page").hidden = page !== "history";
  if (page === "history") {
    await history();
    return;
  }
  if (page === "convert") return;
  $("#account-input").value = drafts[page] || "";
  renderSettings();
  $("#start").textContent = {
    auth: "开始授权 →",
    phone: "开始接码 →",
    pool: "开始推送 →",
  }[page];
  $("#defer").hidden = page !== "pool";
  $$("[data-tab=inspection]").forEach((b) => (b.hidden = page !== "pool"));
  $("#transfer-pool").hidden = page === "pool";
  tab("results");
  renderTask();
}
function tab(name) {
  $$("[data-tab]").forEach((b) =>
    b.classList.toggle("selected", b.dataset.tab === name),
  );
  for (const n of ["results", "logs", "inspection"])
    $("#" + n + "-panel").hidden = n !== name;
}
function renderTask() {
  const t = current;
  const rows = t?.rows || [];
  $("#count").textContent = `${rows.length} 个账号`;
  $("#stat-success").textContent = rows.filter((r) => good(r.state)).length;
  $("#stat-failed").textContent = rows.filter(
    (r) => !good(r.state) && !pending(r.state),
  ).length;
  $("#stat-pending").textContent = rows.filter((r) => pending(r.state)).length;
  $("#run-status").textContent = t?.message || "";
  $("#start").disabled = Boolean(active);
  $("#stop").disabled = !active;
  const searchable = $("#result-search").value.toLowerCase(),
    state = $("#result-state").value;
  const shown = rows.filter(
    (r) =>
      (r.email + " " + r.message).toLowerCase().includes(searchable) &&
      (!state ||
        (state === "success"
          ? good(r.state)
          : state === "failed"
            ? !good(r.state) && !pending(r.state)
            : state === "ready"
              ? pending(r.state)
              : r.state === state)),
  );
  $("#result-rows").innerHTML = shown
    .map(
      (r) =>
        `<tr><td><input type="checkbox" data-row="${esc(r.uid)}" ${selected.has(r.uid) ? "checked" : ""}></td><td>${esc(r.email)}</td><td class="${good(r.state) ? "success" : pending(r.state) ? "" : "error"}">${esc(states[r.state] || r.state)}</td><td>${esc(r.account_id || "—")}</td><td>${esc(r.message)}</td></tr>`,
    )
    .join("");
  $("#result-empty").hidden = Boolean(rows.length);
  $$("[data-row]").forEach(
    (n) =>
      (n.onchange = () =>
        n.checked
          ? selected.add(n.dataset.row)
          : selected.delete(n.dataset.row)),
  );
  $("#logs-panel").textContent = (t?.logs || []).join("\n") || "等待运行日志…";
  $("#progress-bar").style.width = rows.length
    ? (100 * rows.filter((r) => !pending(r.state)).length) / rows.length + "%"
    : "0%";
  for (const id of ["retry", "retry-selected", "defer"])
    $("#" + id).disabled = Boolean(active) || !t?.id;
}
async function poll() {
  if (polling || !csrf) return;
  polling = true;
  const startedPage = page;
  try {
    const status = await api("/status");
    active = status.active;
    if (status.warnings?.length) {
      $("#connection").title = status.warnings.join("\n");
    } else {
      $("#connection").removeAttribute("title");
    }
    $("#connection").textContent = active ? "任务运行中" : "服务已连接";
    if (status.schedule) {
      $("#schedule").textContent = "停用定时";
      $("#inspection-status").textContent =
        "下次巡检：" + new Date(status.schedule.next * 1000).toLocaleString();
    } else {
      $("#schedule").textContent = "启用定时";
      $("#inspection-status").textContent = "定时未启用";
    }
    if (status.inspection)
      $("#inspection-report").textContent = JSON.stringify(
        status.inspection,
        null,
        2,
      );
    if (current?.id) {
      const tid = current.id;
      const t = await api("/tasks/" + tid);
      if (page === startedPage && current?.id === tid) {
        current = t;
        taskByPage[page] = t;
        renderTask();
      }
    } else if (active) {
      const t = await api("/tasks/" + active);
      if (t.kind === page) {
        current = t;
        taskByPage[page] = t;
        renderTask();
      }
    }
    if (["auth", "phone", "pool"].includes(page)) {
      $("#start").disabled = Boolean(active);
      $("#stop").disabled = !active;
    }
    if ($("#browser-dialog").open) await refreshFrame();
  } catch (e) {
    if (csrf) $("#connection").textContent = "连接暂时中断";
  } finally {
    polling = false;
  }
}
async function history() {
  const list = await api("/tasks");
  $("#history-list").innerHTML = list.length
    ? list
        .map(
          (t) =>
            `<div class="history-row"><div><b>${labels[t.kind]} · ${new Date(t.created * 1000).toLocaleString()}</b><small>${esc(t.message)}</small></div><span class="badge">${esc(t.status)}</span><button data-history="${t.id}" class="ghost">打开 →</button></div>`,
        )
        .join("")
    : '<div class="empty">还没有处理任务</div>';
  $$("[data-history]").forEach(
    (b) =>
      (b.onclick = act(async () => {
        const t = await api("/tasks/" + b.dataset.history);
        if (t.kind === "inspect") {
          await navigate("pool");
          tab("inspection");
          $("#inspection-report").textContent = JSON.stringify(
            t.report,
            null,
            2,
          );
          $("#inspection-export").dataset.task = t.id;
        } else {
          taskByPage[t.kind] = t;
          await navigate(t.kind);
        }
      })),
  );
  const status = await api("/status");
  for (const warning of status.warnings || []) {
    const p = document.createElement("p");
    p.className = "warning";
    p.textContent = warning;
    $("#history-list").prepend(p);
  }
  const legacy = await api("/legacy");
  $("#legacy-list").innerHTML =
    legacy
      .map(
        (r, i) =>
          `<div class="history-row"><div><b>${esc(r.kind)}</b><small>${esc(r.path)}</small></div><button data-legacy="${i}" class="ghost">打开</button></div>`,
      )
      .join("") || '<p class="hint">没有迁移记录</p>';
  $$("[data-legacy]").forEach(
    (b) =>
      (b.onclick = act(async () => {
        const data = await api("/legacy/open", "POST", {
          path: legacy[Number(b.dataset.legacy)].path,
        });
        if (data.task) {
          const saved = data.settings;
          Object.assign(configs.pool, saved, {
            model_mode:
              saved.model_whitelist === null
                ? "preserve"
                : saved.model_whitelist.length
                  ? "replace"
                  : "clear",
            model_choices: Object.fromEntries(
              (saved.model_whitelist || []).map((m) => [m, true]),
            ),
          });
          if (configs.pool.site !== data.credential_site) {
            configs.pool.credential = "";
            configs.pool.clear_credential = true;
          }
          taskByPage.pool = data.task;
          await navigate("pool");
          notify("已恢复；核对连接、分组与原待确认写入配置后再重试");
        } else if (data.kind === "convert") {
          await navigate("convert");
          $("#convert-input").value = data.text;
        } else {
          await navigate("pool");
          tab("inspection");
          $("#inspection-report").textContent = data.text;
        }
      })),
  );
}
async function refreshFrame() {
  const r = await fetch("/api/browser/frame", { cache: "no-store" });
  if (r.status === 204) {
    $("#browser-wait").hidden = false;
    return;
  }
  if (!r.ok) return;
  const blob = await r.blob();
  if (frameUrl) URL.revokeObjectURL(frameUrl);
  frameUrl = URL.createObjectURL(blob);
  $("#browser-frame").src = frameUrl;
  $("#browser-wait").hidden = true;
}
async function download(path, method = "GET", data, name = "accounts.json") {
  const blob = await api(path, method, data, true);
  const url = URL.createObjectURL(blob),
    a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function jsonHighlight(value) {
  return esc(JSON.stringify(value, null, 2)).replace(
    /(&quot;[^\n]*?&quot;)(\s*:)?|\b(true|false|null)\b|\b(-?\d+(?:\.\d+)?)\b/g,
    (m, s, key, b, n) =>
      `<span class="${s ? (key ? "json-key" : "json-string") : b ? "json-bool" : "json-number"}">${m}</span>`,
  );
}
async function convert() {
  const r = await api("/convert", "POST", {
    text: $("#convert-input").value,
    target: $("#convert-target").value,
  });
  $("#convert-preview").innerHTML = jsonHighlight(r.preview);
  $("#convert-count").textContent = r.count + " 个账号 · " + r.kind;
  $("#convert-warnings").textContent = r.warnings.join("\n");
  $("#convert-warnings").hidden = !r.warnings.length;
  return r;
}
let fileTarget = "work";
function picker(folder, target) {
  fileTarget = target;
  const input = $(folder ? "#folder-picker" : "#file-picker");
  input.value = "";
  input.click();
}
async function readFiles(event) {
  const files = Array.from(event.target.files).filter((f) =>
    /\.(txt|json)$/i.test(f.name),
  );
  if (files.reduce((n, f) => n + f.size, 0) > 15 * 1024 * 1024)
    throw Error("一次导入不能超过 15 MB");
  const chunks = [],
    errors = [];
  for (const [i, file] of files.entries()) {
    try {
      const text = (await file.text()).replace(/^\uFEFF/, "");
      await api(
        fileTarget === "convert" ? "/convert" : "/preview/" + page,
        "POST",
        { text },
      );
      chunks.push(text);
    } catch (e) {
      errors.push(`第 ${i + 1} 个文件：${e.message}`);
    }
  }
  const target = $(
    fileTarget === "convert" ? "#convert-input" : "#account-input",
  );
  target.value = [target.value, ...chunks].filter(Boolean).join("\n\n");
  notify(
    `导入 ${chunks.length} 个文件${errors.length ? "；跳过 " + errors.length + " 个无效文件" : ""}`,
  );
  if (errors.length) {
    $("#convert-warnings").textContent = errors.join("\n");
    $("#convert-warnings").hidden = false;
    if (fileTarget !== "convert") notify(errors.slice(0, 3).join("；"), true);
  }
}
$("#login-form").onsubmit = async (event) => {
  event.preventDefault();
  try {
    const r = await api("/login", "POST", {
      password: $("#login-password").value,
    });
    csrf = r.csrf;
    $("#login-password").value = "";
    await boot();
  } catch (e) {
    $("#login-error").textContent = e.message;
  }
};
async function boot() {
  settingsReady = false;
  configs = await api("/config");
  countries = await api("/countries");
  $("#login").hidden = true;
  $("#app").hidden = false;
  await navigate(page);
  if (timer) clearInterval(timer);
  timer = setInterval(poll, 1500);
  await poll();
}
$$("[data-page]").forEach(
  (b) => (b.onclick = act(() => navigate(b.dataset.page))),
);
$$("[data-tab]").forEach((b) => (b.onclick = () => tab(b.dataset.tab)));
on("#logout", async () => {
  await api("/logout", "POST", {});
  showLogin();
});
on("#save-settings", async () => {
  await save();
  notify("设置已加密保存");
});
on("#recognize", async () => {
  const rows = await api("/preview/" + page, "POST", {
    text: $("#account-input").value,
  });
  current = {
    rows: rows.map((r, i) => ({ ...r, uid: String(i), state: "ready" })),
    message: "识别完成，确认设置后开始",
  };
  renderTask();
});
on("#start", async () => {
  await save();
  const task = await api("/tasks", "POST", {
    kind: page,
    text: $("#account-input").value,
  });
  current = task;
  taskByPage[page] = task;
  active = task.id;
  selected.clear();
  renderTask();
  if (configs[page].show_browser) notify("可点击“查看登录浏览器”进行手动操作");
});
on("#stop", async () => {
  if (active) await api("/tasks/" + active + "/stop", "POST", {});
  notify("已请求停止，等待当前操作收尾");
});
async function retry(onlySelected) {
  if (!current?.id) return;
  let ids = onlySelected ? [...selected] : null;
  if (onlySelected && !ids.length) throw Error("请先选择账号");
  const rows = current.rows.filter((r) => !ids || ids.includes(r.uid));
  let relogin = false;
  if (
    rows.some(
      (r) =>
        ["refresh_unknown", "refresh_failed", "refreshing"].includes(r.state) ||
        ["refresh_unknown", "refresh_failed"].includes(r.refresh_state),
    )
  )
    relogin = confirm(
      "部分账号刷新失败或结果不明。是否明确重新登录这些账号？取消将保留它们，只重试其他项目。",
    );
  if (!relogin) {
    ids = rows
      .filter(
        (r) =>
          !["refresh_unknown", "refresh_failed", "refreshing"].includes(
            r.state,
          ) && !["refresh_unknown", "refresh_failed"].includes(r.refresh_state),
      )
      .map((r) => r.uid);
    if (!ids.length) throw Error("需要明确选择重新登录后再继续");
  }
  await save();
  current = await api("/tasks/" + current.id + "/retry", "POST", {
    selected: ids,
    relogin,
  });
  active = current.id;
  renderTask();
}
on("#retry", () => retry(false));
on("#retry-selected", () => retry(true));
on("#defer", async () => {
  if (current?.id) {
    current = await api("/tasks/" + current.id + "/defer", "POST", {
      selected: [...selected],
    });
    renderTask();
  }
});
$("#result-search").oninput = renderTask;
$("#result-state").onchange = renderTask;
$("#select-all").onchange = (e) => {
  $$("[data-row]").forEach((n) => {
    n.checked = e.target.checked;
    n.checked ? selected.add(n.dataset.row) : selected.delete(n.dataset.row);
  });
};
on("#clear", () => {
  $("#account-input").value = "";
  current = null;
  taskByPage[page] = null;
  renderTask();
});
on("#import-files", () => picker(false, "work"));
on("#import-folder", () => picker(true, "work"));
$("#file-picker").onchange = act(readFiles);
$("#folder-picker").onchange = act(readFiles);
for (const target of ["pool", "phone"])
  on("#transfer-" + target, async () => {
    if (!current?.id) throw Error("请先打开任务结果");
    const result = await api("/tasks/" + current.id + "/transfer", "POST", {
      target,
      selected: selected.size ? [...selected] : null,
    });
    drafts[target] = result.text;
    await navigate(target);
  });
for (const target of ["sub2", "cpa"])
  on("#export-" + target, async () => {
    if (!current?.id) throw Error("没有任务可导出");
    const check = await api(
      "/tasks/" + current.id + "/export-warnings?target=" + target,
    );
    if (
      check.warnings.length &&
      !confirm(check.warnings.join("\n") + "\n仍按标准格式导出？")
    )
      return;
    await download(
      "/tasks/" + current.id + "/export?target=" + target,
      "GET",
      undefined,
      target === "cpa" ? "cpa-accounts.zip" : "accounts.json",
    );
  });
on("#inspect", async () => {
  await save();
  const t = await api("/tasks", "POST", { kind: "inspect" });
  active = t.id;
  $("#inspection-export").dataset.task = t.id;
  $("#inspection-status").textContent = "正在读取后台状态…";
});
on("#schedule", async () => {
  await save();
  const enabled = $("#schedule").textContent !== "停用定时";
  await api("/inspection/schedule", "POST", {
    enabled,
    minutes: Number($("#inspect-minutes").value),
  });
  await poll();
});
on("#inspection-export", async () => {
  const tasks = await api("/tasks");
  const id =
    $("#inspection-export").dataset.task ||
    tasks.find((t) => t.kind === "inspect" && t.status === "finished")?.id;
  if (!id) throw Error("尚无巡检报告");
  await download(
    "/tasks/" + id + "/export",
    "GET",
    undefined,
    "inspection.json",
  );
});
on("#convert-files", () => picker(false, "convert"));
on("#convert-folder", () => picker(true, "convert"));
on("#convert-clear", () => {
  $("#convert-input").value = "";
  $("#convert-preview").textContent = "结果将在此显示";
  $("#convert-warnings").hidden = true;
});
on("#convert-preview-btn", convert);
on("#convert-save", async () => {
  const r = await convert();
  if (
    r.warnings.length &&
    !confirm("转换存在字段或有效期提示，请先查看提示。仍按标准格式导出？")
  )
    return;
  const target = $("#convert-target").value;
  await download(
    "/convert/export",
    "POST",
    { text: $("#convert-input").value, target },
    target === "cpa" ? "cpa-accounts.zip" : "accounts.json",
  );
});
on("#convert-to-pool", async () => {
  await convert();
  drafts.pool = $("#convert-input").value;
  await navigate("pool");
});
on("#history-refresh", history);
on("#browser-open", async () => {
  $("#browser-dialog").showModal();
  await refreshFrame();
});
on("#browser-close", () => {
  $("#browser-dialog").close();
  $("#browser-text").value = "";
});
$("#browser-frame").onclick = act(async (event) => {
  const rect = event.target.getBoundingClientRect();
  await api("/browser/input", "POST", {
    action: "click",
    x: Math.min(
      1279,
      Math.floor(((event.clientX - rect.left) / rect.width) * 1280),
    ),
    y: Math.min(
      899,
      Math.floor(((event.clientY - rect.top) / rect.height) * 900),
    ),
  });
});
on("#browser-send", async () => {
  await api("/browser/input", "POST", {
    action: "text",
    text: $("#browser-text").value,
  });
  $("#browser-text").value = "";
});
$$("[data-key]").forEach(
  (b) =>
    (b.onclick = act(() =>
      api("/browser/input", "POST", { action: "key", key: b.dataset.key }),
    )),
);
on("#browser-up", () =>
  api("/browser/input", "POST", { action: "scroll", delta: -600 }),
);
on("#browser-down", () =>
  api("/browser/input", "POST", { action: "scroll", delta: 600 }),
);
(async () => {
  try {
    const s = await api("/session");
    csrf = s.csrf;
    await boot();
  } catch {
    showLogin();
  }
})();
