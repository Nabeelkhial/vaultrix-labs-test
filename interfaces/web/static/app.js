// Purpose-driven motion only (Emil's framework): the grade reveal + score count-up
// and a one-time staggered findings reveal are rare, first-view moments. Nothing
// that repeats often animates. All of it is off under prefers-reduced-motion.
(function () {
  "use strict";
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Count a number up to its target (ease-out), for the score.
  function countUp(el) {
    var target = parseFloat(el.getAttribute("data-count"));
    if (isNaN(target)) return;
    if (reduce) { el.textContent = target; return; }
    var dur = 900, t0 = performance.now();
    function tick(now) {
      var p = Math.min(1, (now - t0) / dur);
      var e = 1 - Math.pow(1 - p, 3); // easeOutCubic
      el.textContent = Math.round(target * e);
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  function run() {
    document.querySelectorAll("[data-count]").forEach(countUp);

    var grade = document.querySelector(".grade");
    if (grade && !reduce) grade.classList.add("in-grade");

    // Staggered reveal of findings / rows, once, as they enter.
    var items = [].slice.call(document.querySelectorAll(".reveal"));
    if (reduce || !("IntersectionObserver" in window)) {
      items.forEach(function (n) { n.classList.add("in"); });
      return;
    }
    function reveal(el) {
      if (el.classList.contains("in")) return;
      var i = +(el.getAttribute("data-i") || 0);
      el.style.transitionDelay = Math.min(i * 45, 350) + "ms";
      el.classList.add("in");
    }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { if (en.isIntersecting) { reveal(en.target); io.unobserve(en.target); } });
    }, { threshold: 0, rootMargin: "0px 0px -8% 0px" });
    items.forEach(function (n) {
      // anything already on screen reveals at once; the rest on scroll
      if (n.getBoundingClientRect().top < window.innerHeight) reveal(n);
      else io.observe(n);
    });
    // failsafe: never leave content hidden, whatever happens with the observer
    setTimeout(function () { items.forEach(reveal); }, 1600);
  }
  if (document.readyState !== "loading") run();
  else document.addEventListener("DOMContentLoaded", run);
})();
