(function () {
  "use strict";
  var data = document.getElementById("examples");
  if (data) {
    var cases = JSON.parse(data.textContent);
    var chips = document.getElementById("chips"), out = document.getElementById("case");
    var el = function (t, c, x) { var n = document.createElement(t); if (c) n.className = c; if (x !== undefined) n.textContent = x; return n; };
    var show = function (i) {
      var c = cases[i];
      Array.prototype.forEach.call(chips.children, function (li, j) { li.firstChild.setAttribute("aria-pressed", j === i ? "true" : "false"); });
      while (out.firstChild) out.removeChild(out.firstChild);
      var rows = [["What was sent", c.input, null], ["What AgentShield-X decided", c.verdict_label, c.verdict], ["What gets through", c.output, null]];
      if (c.rules && c.rules.length) rows.push(["Rules that fired", c.rules.join(", "), null]);
      rows.forEach(function (r) {
        var row = el("div", "row"); row.appendChild(el("h3", null, r[0]));
        var p = el(r[2] ? "p" : "pre", r[2] ? "verdict v-" + r[2] : null, r[1]); if (r[2]) p.style.margin = "0"; row.appendChild(p); out.appendChild(row);
      });
    };
    cases.forEach(function (c, i) {
      var li = el("li"), b = el("button", "chip", c.title); b.type = "button"; b.setAttribute("aria-pressed", "false");
      b.addEventListener("click", function () { show(i); }); li.appendChild(b); chips.appendChild(li);
    });
    show(0);
  }
  Array.prototype.forEach.call(document.querySelectorAll("pre.code"), function (pre) {
    var b = document.createElement("button"); b.type = "button"; b.className = "copy"; b.textContent = "Copy";
    b.addEventListener("click", function () {
      var t = pre.querySelector("code").textContent;
      (navigator.clipboard ? navigator.clipboard.writeText(t) : Promise.reject()).then(function () { b.textContent = "Copied"; }, function () { b.textContent = "Press Ctrl+C"; });
      setTimeout(function () { b.textContent = "Copy"; }, 1800);
    });
    pre.appendChild(b);
  });
})();
