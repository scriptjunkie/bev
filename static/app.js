(function () {
  var busy = false;
  var busyKind = "";

  function normalizeCve(raw) {
    var s = (raw || "").trim().replace(/^\/+|\/+$/g, "").toUpperCase();
    if (/^(1999|20\d{2})-(\d{4,7})$/.test(s)) {
      s = "CVE-" + s;
    }
    var m = /^CVE-(1999|20\d{2})-(\d{4,7})$/.exec(s);
    if (!m) {
      return null;
    }
    return { year: m[1], seq: m[2], id: "CVE-" + m[1] + "-" + m[2] };
  }

  function targetUrl(cve) {
    var base = document.body ? document.body.getAttribute("data-base-domain") : "";
    if (base) {
      var port = window.location.port ? ":" + window.location.port : "";
      return (
        window.location.protocol +
        "//cve-" +
        cve.year +
        "-" +
        cve.seq +
        "." +
        base +
        port +
        "/"
      );
    }
    return "/cve/" + cve.id;
  }

  function isRandomHref(href) {
    if (!href) return false;
    try {
      var url = new URL(href, window.location.href);
      return url.pathname === "/random" || url.pathname === "/random/";
    } catch (e) {
      return /\/random\/?$/.test(href);
    }
  }

  function ensureBusyUi() {
    if (document.querySelector(".busy-bar")) return;
    var bar = document.createElement("div");
    bar.className = "busy-bar";
    bar.setAttribute("aria-hidden", "true");
    var status = document.createElement("div");
    status.className = "busy-status";
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    status.setAttribute("aria-atomic", "true");
    document.body.appendChild(bar);
    document.body.appendChild(status);
  }

  function statusEl() {
    return document.querySelector(".busy-status");
  }

  function setButtonBusy(el, label) {
    if (!el || el.getAttribute("data-idle-html") != null) return;
    el.setAttribute("data-idle-html", el.innerHTML);
    el.innerHTML =
      '<span class="busy-spin" aria-hidden="true"></span>' + label;
  }

  function goBusy(kind) {
    if (busy) return false;
    busy = true;
    busyKind = kind;
    ensureBusyUi();
    var message =
      kind === "shirt"
        ? "Making your shirt… this can take a little while."
        : kind === "random"
          ? "Drawing a random CVE… if it's new, naming and the logo can take about 20 seconds."
          : "Coining a name and drawing a logo… this can take about 20 seconds.";
    document.body.classList.add("is-busy");
    document.body.setAttribute("aria-busy", "true");
    var status = statusEl();
    if (status) status.textContent = message;

    var forms = document.querySelectorAll("form.search");
    for (var i = 0; i < forms.length; i++) {
      var form = forms[i];
      form.setAttribute("aria-busy", "true");
      var input = form.querySelector("input");
      var button = form.querySelector("button");
      if (input) input.disabled = true;
      if (button) {
        button.disabled = true;
        setButtonBusy(button, "Coining…");
      }
    }

    var links = document.querySelectorAll("a.btn, a.shirt-buy, a.card-unfiled, a[href]");
    for (var j = 0; j < links.length; j++) {
      var link = links[j];
      var shirt = link.classList.contains("shirt-buy");
      var random = isRandomHref(link.getAttribute("href"));
      var unfiled = link.classList.contains("card-unfiled");
      if (!shirt && !random && !unfiled) continue;
      link.classList.add("is-busy-link");
      link.setAttribute("aria-disabled", "true");
      if (shirt) setButtonBusy(link, "Making your shirt…");
      else if (random && link.classList.contains("btn")) setButtonBusy(link, "Coining…");
    }

    return true;
  }

  function resetBusy() {
    busy = false;
    busyKind = "";
    document.body.classList.remove("is-busy");
    document.body.removeAttribute("aria-busy");
    var status = statusEl();
    if (status) status.textContent = "";

    var forms = document.querySelectorAll("form.search");
    for (var i = 0; i < forms.length; i++) {
      var form = forms[i];
      form.removeAttribute("aria-busy");
      var input = form.querySelector("input");
      var button = form.querySelector("button");
      if (input) input.disabled = false;
      if (button) {
        button.disabled = false;
        if (button.getAttribute("data-idle-html") != null) {
          button.innerHTML = button.getAttribute("data-idle-html");
          button.removeAttribute("data-idle-html");
        }
      }
    }

    var links = document.querySelectorAll("a.is-busy-link");
    for (var j = 0; j < links.length; j++) {
      var link = links[j];
      link.classList.remove("is-busy-link");
      link.removeAttribute("aria-disabled");
      if (link.getAttribute("data-idle-html") != null) {
        link.innerHTML = link.getAttribute("data-idle-html");
        link.removeAttribute("data-idle-html");
      }
    }
  }

  function onSearchSubmit(event) {
    var form = event.currentTarget;
    var input = form.querySelector('input[name="id"]');
    event.preventDefault();
    if (busy) return;
    if (!input) return;
    var cve = normalizeCve(input.value);
    if (!cve) {
      input.setCustomValidity("Enter a CVE id like CVE-2026-1337.");
      input.reportValidity();
      return;
    }
    if (!goBusy("search")) return;
    window.location.assign(targetUrl(cve));
  }

  function onTriggerClick(event) {
    if (event.defaultPrevented) return;
    if (event.button !== 0) return;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    var link = event.currentTarget;
    if (busy) {
      event.preventDefault();
      return;
    }
    var kind = link.classList.contains("shirt-buy")
      ? "shirt"
      : isRandomHref(link.getAttribute("href"))
        ? "random"
        : "search";
    if (!goBusy(kind)) {
      event.preventDefault();
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    ensureBusyUi();
    var forms = document.querySelectorAll("form.search");
    for (var i = 0; i < forms.length; i++) {
      (function (form) {
        var input = form.querySelector('input[name="id"]');
        if (!input) return;
        input.addEventListener("input", function () {
          input.setCustomValidity("");
        });
        form.addEventListener("submit", onSearchSubmit);
      })(forms[i]);
    }

    var clickable = document.querySelectorAll("a.shirt-buy, a.card-unfiled, a[href]");
    for (var j = 0; j < clickable.length; j++) {
      var link = clickable[j];
      if (
        link.classList.contains("shirt-buy") ||
        link.classList.contains("card-unfiled") ||
        isRandomHref(link.getAttribute("href"))
      ) {
        link.addEventListener("click", onTriggerClick);
      }
    }
  });

  window.addEventListener("pageshow", function (event) {
    if (event.persisted || busy) {
      resetBusy();
    }
  });
})();
