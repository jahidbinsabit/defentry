(function() {
    if (typeof scbr_ajax === 'undefined') return;
    var ajaxurl = scbr_ajax.ajaxurl;
    var nonce = scbr_ajax.nonce;

    var passInput = document.getElementById('scbr-pass');
    var submitBtn = document.getElementById('scbr-submit');
    var fb = document.getElementById('scbr-feedback');
    var audio = document.getElementById('scbr-audio');

    if (!passInput || !submitBtn || !fb) return;

    function disableUI(dis) {
        submitBtn.disabled = dis;
        passInput.disabled = dis;
    }

    function removeOverlay() {
        try {
            if (audio) {
                audio.pause();
                audio.currentTime = 0;
            }
        } catch (e) {}
        var ov = document.getElementById('scbr-overlay');
        if (ov) ov.remove();
        document.documentElement.style.overflow = '';
        document.body.style.overflow = '';
    }

    // The password is verified server-side only (wp_check_password).
    // Nothing secret ever lives in this file or the page source.
    function submitPassword(value) {
        fb.textContent = '';
        if (!value) {
            fb.textContent = 'Please enter the password.';
            return;
        }
        disableUI(true);
        var form = new FormData();
        form.append('action', 'scbr_stop_siren');
        form.append('nonce', nonce);
        form.append('pass', value);
        fetch(ajaxurl, { method: 'POST', credentials: 'same-origin', body: form })
            .then(function(res) { return res.json(); })
            .then(function(json) {
                if (json && json.success) {
                    removeOverlay();
                    location.reload();
                } else {
                    fb.textContent = (json && json.data) ? json.data : 'Wrong password.';
                    disableUI(false);
                    passInput.value = '';
                    passInput.focus();
                }
            })
            .catch(function(err) {
                fb.textContent = 'Error verifying password. Try again.';
                disableUI(false);
                if (window.console) console.error(err);
            });
    }

    submitBtn.addEventListener('click', function() {
        submitPassword(passInput.value);
    });

    passInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            submitPassword(passInput.value);
        }
    });
})();
