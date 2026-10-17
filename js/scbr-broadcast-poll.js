/**
 * Defentry realtime broadcast poller.
 *
 * Other logged-in admins must see and hear a new-device alert WITHOUT
 * reloading the page. This polls admin-ajax every 25s; when a broadcast is
 * active and no banner is shown yet, it injects the server-rendered banner
 * HTML plus the siren audio element and attempts playback.
 */
(function() {
    if (typeof scbrPoll === 'undefined' || !scbrPoll.ajaxurl) return;

    var lastToken = '';
    var dismissed = {};
    var checking = false;
    var liveAudio = null;

    function one(sel) { return document.querySelector(sel); }

    function attemptPlay(audio) {
        if (!audio) return;
        try {
            var p = audio.play();
            if (p && p.catch) p.catch(function() { /* autoplay needs interaction */ });
        } catch (e) { /* ignore */ }
    }

    // Browsers block audio before user interaction. The first play() attempt at
    // inject time often fails, so retry on every user interaction afterwards.
    function armInteractionRetry() {
        var handler = function() {
            if (liveAudio && liveAudio.paused) attemptPlay(liveAudio);
        };
        ['mousemove', 'scroll', 'keydown', 'click'].forEach(function(ev) {
            document.addEventListener(ev, handler, { passive: true });
        });
    }

    // Respect manual dismissal: never resurrect a dismissed alert.
    document.addEventListener('click', function(e) {
        var btn = e.target && e.target.closest ? e.target.closest('.scbr-broadcast-notice .notice-dismiss') : null;
        if (!btn) return;
        var notice = btn.closest('.scbr-broadcast-notice');
        if (notice) {
            var t = notice.getAttribute('data-scbr-token') || '';
            if (t) dismissed[t] = true;
            notice.remove();
            var a = document.getElementById('scbr-broadcast-live');
            if (a) { a.pause(); a.remove(); }
            liveAudio = null;
        }
    });

    function inject(data) {
        if (one('.scbr-broadcast-notice')) return;
        var wrap = one('#wpbody-content .wrap') || one('#wpbody-content');
        if (!wrap) return;
        var tmp = document.createElement('div');
        tmp.innerHTML = data.html;
        var notice = tmp.firstElementChild;
        if (!notice) return;
        notice.setAttribute('data-scbr-injected', '1');
        wrap.insertBefore(notice, wrap.firstChild);
        if (data.audio_src) {
            var audio = document.createElement('audio');
            audio.id = 'scbr-broadcast-live';
            audio.loop = true;
            audio.style.display = 'none';
            var src = document.createElement('source');
            src.src = data.audio_src;
            src.type = 'audio/mpeg';
            audio.appendChild(src);
            document.body.appendChild(audio);
            liveAudio = audio;
            attemptPlay(audio);
        }
    }

    function clearInjected() {
        var n = one('.scbr-broadcast-notice[data-scbr-injected="1"]');
        if (n) n.remove();
        var a = document.getElementById('scbr-broadcast-live');
        if (a) { a.pause(); a.remove(); }
        liveAudio = null;
    }

    function check() {
        if (checking) return;
        checking = true;
        var body = 'action=scbr_check_broadcast&nonce=' + encodeURIComponent(scbrPoll.nonce);
        fetch(scbrPoll.ajaxurl, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
            body: body
        }).then(function(r) { return r.json(); }).then(function(res) {
            checking = false;
            if (!res || !res.success) return;
            var d = res.data || {};
            if (d.active && d.token) {
                if (d.token === lastToken) {
                    if (!one('.scbr-broadcast-notice') && !dismissed[d.token] && d.html) inject(d);
                    return;
                }
                lastToken = d.token;
                if (dismissed[d.token]) return;
                if (d.html) inject(d);
            } else {
                clearInjected();
                lastToken = '';
            }
        }).catch(function() { checking = false; });
    }

    var existing = one('.scbr-broadcast-notice');
    if (existing) lastToken = existing.getAttribute('data-scbr-token') || '';

    armInteractionRetry();
    setTimeout(check, 5000);
    setInterval(check, 25000);
})();
