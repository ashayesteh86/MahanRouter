// Language and theme before React starts, so the page does not flash.
try {
  var l = localStorage.getItem("lang") || "fa";
  document.documentElement.lang = l;
  document.documentElement.dir = l === "fa" ? "rtl" : "ltr";
  var th = localStorage.getItem("theme") || "system";
  if (th === "system") th = matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  document.documentElement.dataset.theme = th;
} catch (e) {}
