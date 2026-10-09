/* Spindle baked-in admin console: onboarding token store plus the one
 * SFU toggle page. Plain script, no framework, no animation; the only
 * motion query is the one that opts out of the toggle's state fade.
 */

(function () {
  "use strict";

  // The admin API's SFU switch, primary spelling first. The server also
  // serves every admin route under the Synapse alias, so a 404
  // M_UNRECOGNIZED on the primary falls back to the alias spelling.
  var SFU_PATHS = [
    "/_spindle/admin/v1/rtc/sfu",
    "/_synapse/admin/v1/rtc/sfu",
  ];
  var TOKEN_KEY = "spindle.admin.token";

  var reduceMotion = window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function token() {
    return window.sessionStorage.getItem(TOKEN_KEY) || "";
  }

  function showError(message) {
    var box = document.getElementById("sfu-error");
    box.hidden = false;
    box.textContent = message;
  }

  function clearError() {
    var box = document.getElementById("sfu-error");
    box.hidden = true;
    box.textContent = "";
  }

  function showNotice(message) {
    var box = document.getElementById("sfu-notice");
    if (!message) {
      box.hidden = true;
      box.textContent = "";
      return;
    }
    box.hidden = false;
    box.textContent = message;
  }

  function request(path, init) {
    var headers = { "Content-Type": "application/json" };
    var current = token();
    if (current) {
      headers.Authorization = "Bearer " + current;
    }
    init = init || {};
    init.headers = headers;
    return window.fetch(path, init).then(function (response) {
      return response.json().then(function (body) {
        return { status: response.status, body: body };
      });
    });
  }

  // GET the status document, trying each spelling in turn; the alias
  // only matters when the primary 404s as unrecognized.
  function fetchStatus() {
    var attempts = SFU_PATHS.slice();
    function next() {
      if (attempts.length === 0) {
        return Promise.reject(new Error("the server did not answer on any SFU path"));
      }
      return request(attempts.shift(), { method: "GET" }).then(function (result) {
        if (result.status === 404 &&
            result.body &&
            result.body.errcode === "M_UNRECOGNIZED") {
          return next();
        }
        if (result.status === 401 || result.status === 403) {
          showError("The server refused the token. Save an admin " +
            "access token under Onboarding first.");
          return Promise.reject(new Error("forbidden"));
        }
        if (result.status !== 200) {
          var detail = result.body && result.body.error
            ? result.body.error
            : "HTTP " + result.status;
          return Promise.reject(new Error(detail));
        }
        return result.body;
      });
    }
    return next();
  }

  function text(value) {
    if (value === null || value === undefined) {
      return "—";
    }
    if (typeof value === "object") {
      return JSON.stringify(value);
    }
    return String(value);
  }

  function renderStatus(status) {
    var badge = document.getElementById("sfu-model");
    var model = status.model;
    badge.textContent = model === null || model === undefined
      ? "not configured"
      : String(model);

    var toggle = document.getElementById("sfu-toggle");
    var hint = document.getElementById("sfu-toggle-hint");
    toggle.checked = status.enabled === true;
    // Flipping a switch the server cannot honor would only 400, so the
    // toggle stays disabled until [rtc.livekit] configures the program.
    toggle.disabled = status.configured !== true;
    hint.textContent = status.configured === true
      ? ""
      : "The LiveKit SFU program is not configured — set [rtc.livekit] first.";

    if (status.configured !== true) {
      showNotice("SFU is unconfigured on this server: the switch, the " +
        "minter and the supervised child all read as absent.");
    } else if (status.enabled !== true) {
      showNotice("SFU is switched off: it reads as unconfigured — " +
        "unadvertised, no child, minter paths answer M_UNRECOGNIZED.");
    } else {
      showNotice("");
    }

    var supervised = status.supervised || {};
    var rows = [
      ["Enabled", status.enabled === true ? "on" : "off"],
      ["Configured", status.configured === true ? "yes" : "no"],
      ["Model", text(status.model)],
      ["Stored switch", text(status.switch)],
      ["SFU URL", text(status.sfu_url)],
      ["Token TTL (s)", text(status.token_ttl_seconds)],
      ["Version pin", text(status.version_pin)],
      ["Child health", text(supervised.health)],
      ["Child running", text(supervised.running)],
      ["Held delegations", text(status.held_delegations)],
    ];
    var body = document.getElementById("sfu-status-body");
    while (body.firstChild) {
      body.removeChild(body.firstChild);
    }
    rows.forEach(function (row) {
      var tr = document.createElement("tr");
      var th = document.createElement("th");
      th.scope = "row";
      th.textContent = row[0];
      var td = document.createElement("td");
      if (row[0] === "Enabled") {
        var dot = document.createElement("span");
        dot.className = "status-dot" +
          (status.enabled === true ? "" : " off");
        dot.setAttribute("aria-hidden", "true");
        td.appendChild(dot);
        td.appendChild(document.createTextNode(row[1]));
      } else {
        td.textContent = row[1];
      }
      tr.appendChild(th);
      tr.appendChild(td);
      body.appendChild(tr);
    });
  }

  function refresh() {
    clearError();
    var toggle = document.getElementById("sfu-toggle");
    toggle.disabled = true;
    fetchStatus().then(renderStatus).catch(function (error) {
      if (error && error.message !== "forbidden") {
        showError("Could not load SFU status: " + error.message);
      }
    });
  }

  function putSwitch(path, enabled) {
    return request(path, {
      method: "PUT",
      body: JSON.stringify({ enabled: enabled }),
    }).then(function (result) {
      if (result.status === 404 &&
          result.body && result.body.errcode === "M_UNRECOGNIZED") {
        return { unrecognized: true };
      }
      if (result.status !== 200) {
        var detail = result.body && result.body.error
          ? result.body.error
          : "HTTP " + result.status;
        return { failed: detail };
      }
      return { status: result.body };
    });
  }

  function setSwitch(enabled) {
    clearError();
    var attempts = SFU_PATHS.slice();
    function next() {
      if (attempts.length === 0) {
        showError("The server did not answer on any SFU path.");
        refresh();
        return;
      }
      putSwitch(attempts.shift(), enabled).then(function (outcome) {
        if (outcome.unrecognized) {
          next();
        } else if (outcome.failed) {
          showError("Could not flip the SFU switch: " + outcome.failed);
          refresh();
        } else {
          renderStatus(outcome.status);
        }
      }).catch(function (error) {
        showError("Could not flip the SFU switch: " + error.message);
        refresh();
      });
    }
    next();
  }

  function refreshTokenState() {
    var state = document.getElementById("token-state");
    state.textContent = token()
      ? "A token is saved for this tab."
      : "No token saved.";
  }

  document.addEventListener("DOMContentLoaded", function () {
    var form = document.getElementById("token-form");
    var input = document.getElementById("token-input");
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      window.sessionStorage.setItem(TOKEN_KEY, input.value.trim());
      input.value = "";
      refreshTokenState();
      refresh();
    });
    document.getElementById("token-clear").addEventListener("click", function () {
      window.sessionStorage.removeItem(TOKEN_KEY);
      refreshTokenState();
      refresh();
    });
    document.getElementById("sfu-refresh").addEventListener("click", refresh);
    document.getElementById("sfu-toggle").addEventListener("change", function (event) {
      setSwitch(event.target.checked);
    });
    // The toggle has no entrance animation; this read keeps the
    // reduced-motion contract explicit for future edits.
    if (reduceMotion) {
      document.documentElement.classList.add("reduced-motion");
    }
    refreshTokenState();
    refresh();
  });
})();
