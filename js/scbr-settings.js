(function($) {
    if (typeof scbr_ajax === 'undefined') {
        console.error('Defentry: scbr_ajax not defined.');
        return;
    }

    // Broadcast banner actions (block/unblock, trust, mute)
    $(document).on('click', '.scbr-action', function(e) {
        e.preventDefault();
        const $btn = $(this);
        const action = $btn.data('action');
        const userId = $btn.data('user-id');
        const deviceId = $btn.data('device-id');
        const nonce = $btn.data('nonce');
        const audio = $('#scbr-broadcast')[0] || $('#scbr-broadcast-live')[0];
        $btn.prop('disabled', true);

        let ajaxAction = '';
        if (action === 'block') {
            ajaxAction = 'scbr_block_user';
        } else if (action === 'unblock') {
            ajaxAction = 'scbr_unblock_user';
        } else if (action === 'trust') {
            ajaxAction = 'scbr_trust_device';
        } else {
            console.error('Defentry: Unknown action', action);
            $btn.prop('disabled', false);
            return;
        }

        const data = {
            action: ajaxAction,
            nonce: nonce,
            target_user_id: userId
        };
        if (action === 'trust') data.device_id = deviceId;

        $.post(scbr_ajax.ajaxurl, data, function(response) {
            if (response.success) {
                if (audio) {
                    audio.pause();
                    audio.currentTime = 0;
                }
                $btn.closest('.scbr-broadcast-notice').remove();
                location.reload();
            } else {
                console.error('Defentry: Action failed:', response.data || 'Unknown error');
                alert(response.data || 'Action failed.');
                $btn.prop('disabled', false);
            }
        }).fail(function(jqXHR, textStatus, errorThrown) {
            console.error('Defentry: AJAX error:', textStatus, errorThrown);
            alert('Network error occurred. Please try again.');
            $btn.prop('disabled', false);
        });
    });

    // Unblock user from settings page
    $(document).on('click', '.scbr-unblock-user', function(e) {
        e.preventDefault();
        const $btn = $(this);
        const userId = $btn.data('user-id');
        const nonce = $btn.data('nonce');
        $btn.prop('disabled', true);

        $.post(scbr_ajax.ajaxurl, {
            action: 'scbr_unblock_user',
            nonce: nonce,
            target_user_id: userId
        }, function(response) {
            if (response.success) {
                $btn.closest('li').remove();
            } else {
                console.error('Defentry: Unblock failed:', response.data || 'Unknown error');
                alert(response.data || 'Failed to unblock user.');
                $btn.prop('disabled', false);
            }
        }).fail(function(jqXHR, textStatus, errorThrown) {
            console.error('Defentry: Unblock AJAX error:', textStatus, errorThrown);
            alert('Network error occurred. Please try again.');
            $btn.prop('disabled', false);
        });
    });

    // Mute siren
    $(document).on('click', '.scbr-mute', function(e) {
        e.preventDefault();
        const $btn = $(this);
        const nonce = $btn.data('nonce');
        const audio = $('#scbr-broadcast')[0] || $('#scbr-broadcast-live')[0];
        $btn.prop('disabled', true);

        $.post(scbr_ajax.ajaxurl, {
            action: 'scbr_mute_siren',
            nonce: nonce
        }, function(response) {
            if (response.success) {
                if (audio) {
                    audio.pause();
                    audio.currentTime = 0;
                }
                $btn.text('Siren Muted');
            } else {
                console.error('Defentry: Mute failed:', response.data || 'Unknown error');
                alert(response.data || 'Failed to mute siren.');
                $btn.prop('disabled', false);
            }
        }).fail(function(jqXHR, textStatus, errorThrown) {
            console.error('Defentry: Mute AJAX error:', textStatus, errorThrown);
            alert('Network error occurred. Please try again.');
            $btn.prop('disabled', false);
        });
    });

    // Unmute siren (re-enables the broadcast siren after it was muted)
    $(document).on('click', '.scbr-unmute', function(e) {
        e.preventDefault();
        const $btn = $(this);
        const nonce = $btn.data('nonce');
        $btn.prop('disabled', true);

        $.post(scbr_ajax.ajaxurl, {
            action: 'scbr_unmute_siren',
            nonce: nonce
        }, function(response) {
            if (response.success) {
                location.reload();
            } else {
                console.error('Defentry: Unmute failed:', response.data || 'Unknown error');
                alert(response.data || 'Failed to unmute siren.');
                $btn.prop('disabled', false);
            }
        }).fail(function(jqXHR, textStatus, errorThrown) {
            console.error('Defentry: Unmute AJAX error:', textStatus, errorThrown);
            alert('Network error occurred. Please try again.');
            $btn.prop('disabled', false);
        });
    });

    // Block IP from the broadcast banner (master admin): instantly blocks the
    // IP tied to the active new-device alert for 1 hour.
    $(document).on('click', '.scbr-block-ip', function(e) {
        e.preventDefault();
        const $btn = $(this);
        const nonce = $btn.data('nonce');
        if (!confirm('Block the IP from this login alert instantly? That device will be locked out for 1 hour.')) {
            return;
        }
        $btn.prop('disabled', true);

        $.post(scbr_ajax.ajaxurl, {
            action: 'scbr_block_ip',
            nonce: nonce
        }, function(response) {
            if (response.success) {
                const audio = $('#scbr-broadcast')[0] || $('#scbr-broadcast-live')[0];
                if (audio) {
                    audio.pause();
                    audio.currentTime = 0;
                }
                $btn.closest('.scbr-broadcast-notice').remove();
                location.reload();
            } else {
                console.error('Defentry: Block IP failed:', response.data || 'Unknown error');
                alert(response.data || 'Failed to block IP.');
                $btn.prop('disabled', false);
            }
        }).fail(function(jqXHR, textStatus, errorThrown) {
            console.error('Defentry: Block IP AJAX error:', textStatus, errorThrown);
            alert('Network error occurred. Please try again.');
            $btn.prop('disabled', false);
        });
    });

    // Media uploader for audio
    $('#upload_audio_button').on('click', function(e) {
        e.preventDefault();
        var frame = wp.media({
            title: 'Select Siren Audio',
            button: { text: 'Use this audio' },
            multiple: false,
            library: { type: 'audio/mpeg' }
        });
        frame.on('select', function() {
            var attachment = frame.state().get('selection').first().toJSON();
            $('#custom_audio_url').val(attachment.url);
        });
        frame.open();
    });

    // Clear custom audio
    $('#clear_audio').on('click', function(e) {
        e.preventDefault();
        $('#custom_audio_url').val('');
    });

    // Remove specific device
    $(document).on('click', '.scbr-remove-device', function(e) {
        e.preventDefault();
        const $btn = $(this);
        const userId = $btn.data('user-id');
        const deviceId = $btn.data('device-id');
        const nonce = $btn.data('nonce');
        $btn.prop('disabled', true);

        $.post(scbr_ajax.ajaxurl, {
            action: 'scbr_remove_device',
            nonce: nonce,
            target_user_id: userId,
            device_id: deviceId
        }, function(response) {
            if (response.success) {
                $btn.closest('li').remove();
            } else {
                console.error('Defentry: Remove device failed:', response.data || 'Unknown error');
                alert(response.data || 'Failed to remove device.');
                $btn.prop('disabled', false);
            }
        }).fail(function(jqXHR, textStatus, errorThrown) {
            console.error('Defentry: Remove device AJAX error:', textStatus, errorThrown);
            alert('Network error occurred. Please try again.');
            $btn.prop('disabled', false);
        });
    });
})(jQuery);
/* ---------- Defentry v2: tabbed settings UI ---------- */
(function($) {
    var $tabs = $('.scbr2-tabs [data-scbr-tab]');
    var $panels = $('[data-scbr-panel]');
    if (!$tabs.length || !$panels.length) return;

    function activateTab(id, persist) {
        $tabs.each(function() {
            $(this).toggleClass('nav-tab-active', $(this).data('scbr-tab') === id);
        });
        $panels.each(function() {
            var show = $(this).data('scbr-panel') === id;
            $(this).prop('hidden', !show);
        });
        if (persist !== false) {
            try { sessionStorage.setItem('scbr2_tab', id); } catch (e) {}
        }
    }

    $tabs.on('click', function(e) {
        e.preventDefault();
        activateTab($(this).data('scbr-tab'));
    });
    // Tile "Manage →" links also switch tabs.
    $('[data-scbr-tab].scbr2-tile-link').on('click', function(e) {
        e.preventDefault();
        activateTab($(this).data('scbr-tab'));
    });

    // Restore the tab the user was on before saving (the save redirect
    // always lands on the default tab).
    try {
        var saved = sessionStorage.getItem('scbr2_tab');
        var fromUrl = new URLSearchParams(window.location.search).get('scbr_tab');
        if (fromUrl) {
            activateTab(fromUrl, false);
        } else if (saved && $('[data-scbr-tab="' + saved + '"]').length) {
            activateTab(saved, false);
        }
    } catch (e) {}
})(jQuery);

/* ---------- Defentry v2: setup wizard step navigation ---------- */
(function() {
    var form = document.getElementById('scbr2-wizard-form');
    if (!form) return;

    function showPane(n) {
        form.querySelectorAll('[data-scbr-wpane]').forEach(function(pane) {
            pane.hidden = pane.getAttribute('data-scbr-wpane') !== String(n);
        });
        form.querySelectorAll('[data-scbr-wstep]').forEach(function(step) {
            var sn = parseInt(step.getAttribute('data-scbr-wstep'), 10);
            step.classList.toggle('is-active', sn === n);
            step.classList.toggle('is-done', sn < n);
        });
        var first = form.querySelector('[data-scbr-wpane="' + n + '"] input');
        if (first) first.focus();
    }

    form.querySelectorAll('[data-scbr-wnext]').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var pass = document.getElementById('scbr2-wizard-pass');
            if (pass && !pass.value) {
                pass.focus();
                pass.reportValidity();
                return;
            }
            showPane(parseInt(btn.getAttribute('data-scbr-wnext'), 10));
        });
    });
    form.querySelectorAll('[data-scbr-wprev]').forEach(function(btn) {
        btn.addEventListener('click', function() {
            showPane(parseInt(btn.getAttribute('data-scbr-wprev'), 10));
        });
    });
})();
