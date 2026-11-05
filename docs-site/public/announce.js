/*! Frensense announcement embed (bar + popup). SPDX-License-Identifier: GPL-3.0-only
 *
 * Drop this on any Friehub site (marketing site, app, docs) to show the same
 * announcements the docs site shows:
 *
 *   <script src="https://frensense.friehub.cloud/announce.js" defer></script>
 *
 * The popup lives in a shadow root, so the host page's CSS cannot break it and
 * it cannot break the host page. Text is set with textContent only and URLs
 * must be https:// or a path on the feed's origin, so the feed cannot inject
 * markup or script.
 */
(function () {
  'use strict';

  var origin = (document.location ? document.location : window.location).origin;
  var script = document.currentScript || (function () { var s = document.getElementsByTagName('script'); return s[s.length - 1]; })();
  var src = (script && script.getAttribute('data-src')) || origin + '/announcements.json';
  var KEY = 'frensense:dismissed-announcements';
  var DAY = 86400000;
  var colors = { brand: '#1dc95e', info: '#20acff', warn: '#ff713f' };

  function dismissed() {
    try { var v = JSON.parse(localStorage.getItem(KEY) || '[]'); return Array.isArray(v) ? v : []; }
    catch (e) { return []; }
  }
  function remember(id) {
    try { localStorage.setItem(KEY, JSON.stringify(dismissed().concat(id))); } catch (e) {}
  }
  function active(a, now) {
    if (a.start && now < Date.parse(a.start + 'T00:00:00Z')) return false;
    if (a.end && now >= Date.parse(a.end + 'T00:00:00Z') + DAY) return false;
    return true;
  }
  function safeUrl(u) {
    if (typeof u !== 'string') return null;
    if (u.charAt(0) === '/' && u.charAt(1) !== '/') return origin + u;
    return /^https:\/\//i.test(u) ? u : null;
  }
  function pick(list, display, seen, now) {
    for (var i = 0; i < list.length; i++) {
      var a = list[i];
      if (a && a.id && a.message && (a.display || 'bar') === display &&
          active(a, now) && seen.indexOf(a.id) < 0) return a;
    }
  }
  function el(tag, text, css) {
    var n = document.createElement(tag);
    if (text) n.textContent = text;
    if (css) n.style.cssText = css;
    return n;
  }

  function renderBar(a) {
    var bar = el('div', '', 'position:relative;display:flex;align-items:center;justify-content:center;' +
      'min-height:44px;padding:8px 48px;box-sizing:border-box;font:600 14px/1.3 system-ui,sans-serif;' +
      'color:#0b100d;text-align:center;background:' + (colors[a.tone] || colors.brand));
    bar.setAttribute('role', 'region');
    bar.setAttribute('aria-label', 'Announcement');
    var p = document.createElement('span');
    p.style.cssText = 'line-height:1.3;color:inherit;display:block';
    p.textContent = a.message;
    bar.appendChild(p);
    if (a.link) {
      var lnk = el('a', a.link.text + ' &rarr;', 'margin-top:6px;color:#0b100d;text-decoration:none;font-weight:600');
      lnk.href = safeUrl(a.link.href) || '#';
      bar.appendChild(lnk);
    }
    var cl = el('button', '&times;', 'position:absolute;top:6px;right:10px;cursor:pointer;border:0;background:transparent;color:#0b100d;font-size:18px;line-height:1;');
    cl.setAttribute('aria-label', 'Dismiss announcement');
    cl.addEventListener('click', function () { remember(a.id); document.body.removeChild(bar); });
    bar.appendChild(cl);
    return bar;
  }

  function renderPopup(a) {
    var root = document.createElement('div');
    root.style.cssText = 'all:inherit;position:fixed;inset:0;z-index:200';
    var shadow = root.attachShadow({ mode: 'open' });

    var backdrop = el('div', '', 'position:fixed;inset:0;z-index:0;background:rgba(11,16,13,0.6);display:flex;align-items:center;justify-content:center;padding:16px;');
    var pop = el('div', '', 'position:relative;display:flex;flex-direction:column;width:min(440px,100%);height:min(480px,100%);overflow:hidden;border-radius:12px;background:#fff;color:#0b100d;box-shadow:0 24px 60px rgba(0,0,0,0.35);');
    if (a.image) {
      var img = el('img', '', 'flex:0 0 50%;width:100%;min-height:0;object-fit:cover;display:block;');
      img.src = safeUrl(a.image.src) || a.image.src;
      img.alt = a.image.alt || '';
      pop.appendChild(img);
      var body = el('div', '', 'flex:1 1 50%;min-height:0;box-sizing:border-box;display:flex;flex-direction:column;gap:8px;padding:18px 22px 20px;overflow:auto;');
      body.className = 'no-img';
      if (a.title) {
        var t = el('h2', '', 'margin:0;border:0;padding:0;font-size:22px;line-height:1.2;font-weight:800;');
        t.textContent = a.title;
        body.appendChild(t);
      }
      var txt = el('p', '', 'margin:0;font-size:15px;line-height:1.45;color:#4a524c;');
      txt.textContent = a.message;
      body.appendChild(txt);
      if (a.link) {
        var cta = el('a', a.link.text + ' &rarr;', 'margin-top:auto;align-self:flex-start;padding:9px 16px;border-radius:8px;background:#0b100d;color:#f1f5f2;font-weight:700;font-size:14px;text-decoration:none;');
        cta.href = safeUrl(a.link.href) || '#';
        body.appendChild(cta);
      }
      pop.appendChild(body);
    } else {
      var body = el('div', '', 'flex:1 1 50%;min-height:0;box-sizing:border-box;display:flex;flex-direction:column;gap:8px;padding:18px 22px 20px;overflow:auto;justify-content:center;');
      if (a.title) {
        var t = el('h2', '', 'margin:0;border:0;padding:0;font-size:22px;line-height:1.2;font-weight:800;');
        t.textContent = a.title;
        body.appendChild(t);
      }
      var txt = el('p', '', 'margin:0;font-size:15px;line-height:1.45;color:#4a524c;');
      txt.textContent = a.message;
      body.appendChild(txt);
      if (a.link) {
        var cta = el('a', a.link.text + ' &rarr;', 'margin-top:auto;align-self:flex-start;padding:9px 16px;border-radius:8px;background:#0b100d;color:#f1f5f2;font-weight:700;font-size:14px;text-decoration:none;');
        cta.href = safeUrl(a.link.href) || '#';
        body.appendChild(cta);
      }
      pop.appendChild(body);
    }
    var cl = el('button', '&times;', 'position:absolute;top:10px;right:10px;z-index:1;width:32px;height:32px;border:0;border-radius:50%;background:#0b100d;color:#f1f5f2;font-size:20px;line-height:1;cursor:pointer;');
    cl.setAttribute('aria-label', 'Close');
    cl.addEventListener('click', function () { remember(a.id); document.body.removeChild(root); });
    pop.appendChild(cl);
    backdrop.appendChild(pop);
    shadow.appendChild(backdrop);
    return root;
  }

  function show(popup) {
    var host = document.body || document.documentElement;
    var existing = document.querySelector('div[data-frensense-popup]');
    if (existing) host.removeChild(existing);
    if (popup) {
      var node = renderPopup(popup);
      node.setAttribute('data-frensense-popup', '1');
      host.appendChild(node);
      var cl = node.querySelector('.pop-close');
      if (cl) setTimeout(function () { cl.focus(); }, 1200);
      var onKey = function (e) { if (e.key === 'Escape') { document.body.removeChild(node); document.removeEventListener('keydown', onKey); } };
      document.addEventListener('keydown', onKey, { once: true });
    }
  }

  function run() {
    var req = new XMLHttpRequest();
    req.open('GET', src, true);
    req.onerror = function () { /* keep the routine quiet; render what we can */ };
    req.onload = function () {
      var list = [];
      try { list = JSON.parse(req.responseText).announcements || []; } catch (e) { /* keep quiet */ }
      var seen = dismissed();
      var bar = pick(list, 'bar', seen);
      var popup = pick(list, 'popup', seen);

      if (bar) {
        var node = renderBar(bar);
        document.body.appendChild(node);
        var cl = node.querySelector('button');
        if (cl) cl.addEventListener('click', function () { remember(bar.id); document.body.removeChild(node); });
      }

      if (popup) {
        setTimeout(function () { show(popup); }, 1200);
      }
    };
    req.send();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run, { once: true });
  } else {
    run();
  }
})();
