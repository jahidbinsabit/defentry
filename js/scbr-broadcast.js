(function() {
    const audio = document.getElementById('scbr-broadcast');
    if (!audio) return;

    let hasInteracted = false;
    let playTimeout = null;

    const attemptPlay = () => {
        if (hasInteracted && !audio.paused) return;
        audio.play().catch(e => {
            console.log('Defentry: Audio play failed after interaction:', e);
        });
    };

    const interactions = ['mousemove', 'scroll', 'keydown', 'click'];
    interactions.forEach(event => {
        document.addEventListener(event, () => {
            if (!hasInteracted) {
                hasInteracted = true;
                attemptPlay();
            }
        }, { once: true, passive: true });
    });

    playTimeout = setTimeout(attemptPlay, 500);
})();