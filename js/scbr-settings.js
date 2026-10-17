(function($) {
    if (typeof scbr_ajax === 'undefined') {
        console.error('Defentry: scbr_ajax not defined.');
        return;
    }

    // Broadcast banner actions (block/unblock, trust, mute)
    $('.scbr-action').on('click', function(e) {
        e.preventDefault();
        const $btn = $(this);
        const action = $btn.data('action');
        const userId = $btn.data('user-id');
        const deviceId = $btn.data('device-id');
        const nonce = $btn.data('nonce');
        const audio = $('#scbr-broadcast')[0];
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
    $('.scbr-unblock-user').on('click', function(e) {
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
    $('.scbr-mute').on('click', function(e) {
        e.preventDefault();
        const $btn = $(this);
        const nonce = $btn.data('nonce');
        const audio = $('#scbr-broadcast')[0];
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
    $('.scbr-remove-device').on('click', function(e) {
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