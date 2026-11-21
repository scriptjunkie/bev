(function () {
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

  function showShirtStatus(root, message) {
    var status = root.querySelector(".shirt-status");
    if (!status) return;
    if (message) {
      status.hidden = false;
      status.textContent = message;
    } else {
      status.hidden = true;
      status.textContent = "";
    }
  }

  function isTeemillUrl(url) {
    try {
      var parsed = new URL(url);
      if (parsed.protocol !== "https:") return false;
      var host = parsed.hostname.toLowerCase();
      return host === "teemill.com" || host.endsWith(".teemill.com");
    } catch (e) {
      return false;
    }
  }

  function rememberProduct(saveUrl, productUrl) {
    if (!saveUrl || !isTeemillUrl(productUrl)) return;
    fetch(saveUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: productUrl }),
    }).catch(function () {});
  }

  function bindShirt(root) {
    var button = root.querySelector(".shirt-buy");
    if (!button) return;
    var idleLabel = button.textContent;
    button.addEventListener("click", function (event) {
      event.preventDefault();
      var cached = root.getAttribute("data-product-url");
      if (cached && isTeemillUrl(cached)) {
        window.open(cached, "_blank", "noopener");
        return;
      }
      var key = root.getAttribute("data-teemill-key") || "";
      var printUrl = root.getAttribute("data-print-url") || "";
      var name = root.getAttribute("data-name") || "Brand Every Vuln";
      var description = root.getAttribute("data-description") || "";
      if (!key || !printUrl) {
        showShirtStatus(root, "The T-shirt desk isn't set up on this server.");
        return;
      }
      button.disabled = true;
      button.textContent = "Creating your shirt…";
      showShirtStatus(root, "");
      var newTab = window.open("about:blank", "_blank");
      if (newTab) {
        try {
          newTab.document.write("Creating your T-shirt…");
          newTab.document.close();
        } catch (e) {}
      }
      fetch("https://teemill.com/omnis/v3/product/create", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer " + key,
        },
        body: JSON.stringify({
          image_url: printUrl,
          item_code: "RNA1",
          colours: "White",
          name: name,
          description: description,
          price: 20.0,
        }),
      })
        .then(function (response) {
          return response.json().then(function (body) {
            return { ok: response.ok, body: body };
          });
        })
        .then(function (result) {
          var url = result.body && result.body.url;
          if (!result.ok || !url || !isTeemillUrl(url)) {
            var message =
              (result.body && (result.body.message || result.body.error)) ||
              "Teemill couldn't create that shirt. Try again in a moment.";
            throw new Error(message);
          }
          root.setAttribute("data-product-url", url);
          rememberProduct(root.getAttribute("data-save-url"), url);
          if (newTab && !newTab.closed) {
            newTab.location.href = url;
          } else {
            window.location.assign(url);
          }
        })
        .catch(function (err) {
          if (newTab && !newTab.closed) {
            try {
              newTab.close();
            } catch (e) {}
          }
          showShirtStatus(
            root,
            (err && err.message) || "Teemill couldn't create that shirt. Try again in a moment."
          );
        })
        .then(function () {
          button.disabled = false;
          button.textContent = idleLabel;
        });
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var forms = document.querySelectorAll("form.search");
    for (var i = 0; i < forms.length; i++) {
      (function (form) {
        var input = form.querySelector('input[name="id"]');
        if (!input) return;
        input.addEventListener("input", function () {
          input.setCustomValidity("");
        });
        form.addEventListener("submit", function (event) {
          event.preventDefault();
          var cve = normalizeCve(input.value);
          if (!cve) {
            input.setCustomValidity("Enter a CVE id like CVE-2026-1337.");
            input.reportValidity();
            return;
          }
          window.location.assign(targetUrl(cve));
        });
      })(forms[i]);
    }
    var merch = document.querySelectorAll("section.merch");
    for (var j = 0; j < merch.length; j++) {
      bindShirt(merch[j]);
    }
  });
})();
