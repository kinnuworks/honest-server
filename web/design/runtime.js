/*
  runtime.js: flags the page's effects read, plus three helpers.
  Load it in <head> without defer so the flags are set before first paint:
    <script src="/design/runtime.js"></script>
  No dependencies. Works in plain pages and inside React apps.

  Flags on <html>:
    data-js                 scripts are running (reveal animations may hide content)
    data-motion="reduce"    OS reduced-motion setting, or ?motion=reduce
    data-record             ?record=1: slower key transitions, no grain
    data-webgl="yes|no"     WebGL available; ?webgl=0 forces the fallback
    data-lite               slow device, data saver, or ?lite=1: heavy effects off

  Helpers on window.design:
    afterFirstScreen(fn)    run fn once the first screen has painted and the
                            browser is idle; load heavy effects here
    whenVisible(el, start, stop)
                            start an effect only while el is on screen and the
                            tab is visible; returns a function that disconnects
    onReplay(fn)            press R (outside a text field) to replay the
                            signature moment during a demo
*/
(function () {
  var root = document.documentElement;
  var q = new URLSearchParams(location.search);
  var mq = window.matchMedia ? matchMedia("(prefers-reduced-motion: reduce)") : { matches: false };

  root.setAttribute("data-js", "");

  function setMotion() {
    var reduce = q.get("motion") === "reduce" || mq.matches;
    if (reduce) root.setAttribute("data-motion", "reduce");
    else root.removeAttribute("data-motion");
    design.reduce = reduce;
  }

  function hasWebGL() {
    if (q.get("webgl") === "0") return false;
    try {
      var c = document.createElement("canvas");
      return !!(window.WebGLRenderingContext && (c.getContext("webgl2") || c.getContext("webgl")));
    } catch (e) { return false; }
  }

  var conn = navigator.connection || {};
  var lite = q.has("lite") || conn.saveData === true ||
    (navigator.deviceMemory && navigator.deviceMemory < 4) ||
    (navigator.hardwareConcurrency && navigator.hardwareConcurrency <= 2);

  var design = window.design = {
    reduce: false,
    record: q.has("record"),
    webgl: hasWebGL(),
    lite: !!lite,
    afterFirstScreen: function (fn) {
      function idle() { (window.requestIdleCallback || function (f) { setTimeout(f, 200); })(fn, { timeout: 1500 }); }
      if (document.readyState === "complete") idle();
      else addEventListener("load", idle, { once: true });
    },
    whenVisible: function (el, start, stop) {
      var onScreen = false, running = false;
      function sync() {
        var want = onScreen && !document.hidden;
        if (want && !running) { running = true; start(); }
        else if (!want && running) { running = false; if (stop) stop(); }
      }
      var io = new IntersectionObserver(function (entries) { onScreen = entries[0].isIntersecting; sync(); }, { threshold: 0.01 });
      io.observe(el);
      document.addEventListener("visibilitychange", sync);
      return function () { io.disconnect(); document.removeEventListener("visibilitychange", sync); if (running && stop) stop(); };
    },
    onReplay: function (fn) {
      addEventListener("keydown", function (e) {
        var t = e.target;
        var typing = t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
        if (!typing && !e.metaKey && !e.ctrlKey && !e.altKey && (e.key === "r" || e.key === "R")) fn();
      });
    }
  };

  setMotion();
  if (mq.addEventListener) mq.addEventListener("change", setMotion);
  if (design.record) root.setAttribute("data-record", "");
  root.setAttribute("data-webgl", design.webgl ? "yes" : "no");
  if (design.lite) root.setAttribute("data-lite", "");

  // Frame-rate probe after load: if the page can't hold ~40 fps, switch heavy
  // effects off and tell listeners (they should stop their render loops).
  design.afterFirstScreen(function () {
    if (design.lite || document.hidden || !window.requestAnimationFrame) return;
    var gaps = [], last = 0;
    function tick(now) {
      if (last) gaps.push(now - last);
      last = now;
      if (gaps.length < 40) return requestAnimationFrame(tick);
      gaps.sort(function (a, b) { return a - b; });
      if (!document.hidden && gaps[20] > 25) {
        design.lite = true;
        root.setAttribute("data-lite", "");
        dispatchEvent(new Event("design:lite"));
      }
    }
    requestAnimationFrame(tick);
  });
})();
