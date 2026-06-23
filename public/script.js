'use strict';

(function () {
  const form = document.getElementById('participation-form');
  const csrfInput = document.getElementById('csrf');
  const errorBox = document.getElementById('form-error');
  const submitBtn = document.getElementById('submit-btn');
  const submitLabel = document.getElementById('submit-label');
  const formSection = document.getElementById('form-section');
  const debriefSection = document.getElementById('debrief-section');

  // Recupere un jeton CSVF lie a la session.
  fetch('/api/init', { credentials: 'same-origin' })
    .then((r) => r.json())
    .then((d) => {
      if (d && d.csrfToken) csrfInput.value = d.csrfToken;
    })
    .catch(() => {
      /* le serveur renverra une erreur a la soumission si besoin */
    });

  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.hidden = false;
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    errorBox.hidden = true;
    submitBtn.disabled = true;
    submitLabel.textContent = 'Envoi en cours...';

    const payload = {
      _csrf: csrfInput.value,
      nom: form.nom.value,
      prenom: form.prenom.value,
      service: form.service.value,
      fonction: form.fonction.value,
      reponse: form.reponse.value,
    };

    try {
      const res = await fetch('/api/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(payload),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        showError(data.error || 'Une erreur est survenue. Reessayez.');
        submitBtn.disabled = false;
        submitLabel.textContent = 'Envoyer ma reponse';
        return;
      }

      // Succes : on affiche l'ecran pedagogique.
      formSection.hidden = true;
      debriefSection.hidden = false;
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (err) {
      showError('Impossible de contacter le serveur. Verifiez votre connexion.');
      submitBtn.disabled = false;
      submitBtn.textContent = 'Envoyer ma reponse';
    }
  });
})();
