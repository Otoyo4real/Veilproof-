// Shared header navigation: mobile menu toggle. No dependencies.
// The button toggles the nav-open class on the header and keeps
// aria-expanded in sync. Tapping a nav link closes the menu.
(function () {
  'use strict';
  function init() {
    var header = document.querySelector('.site-header');
    var toggle = document.querySelector('.nav-toggle');
    var nav = document.getElementById('siteNav');
    if (!header || !toggle || !nav) return;
    toggle.addEventListener('click', function () {
      var open = header.classList.toggle('nav-open');
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    nav.addEventListener('click', function (event) {
      if (event.target && event.target.tagName === 'A') {
        header.classList.remove('nav-open');
        toggle.setAttribute('aria-expanded', 'false');
      }
    });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
