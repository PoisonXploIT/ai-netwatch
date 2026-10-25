// Tema antes del primer paint (evita flash): localStorage > prefers-color-scheme.
// Externo a proposito: permite una CSP estricta (script-src 'self') sin
// 'unsafe-inline'. Se carga en el <head>, sincronico, antes del body.
(function () {
  var t = null;
  try { t = localStorage.getItem("anw-theme"); } catch (e) { /* modo privado */ }
  if (t !== "dark" && t !== "light") {
    t = window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  document.documentElement.setAttribute("data-theme", t);
})();
