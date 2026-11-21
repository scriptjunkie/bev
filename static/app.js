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
  });
})();
