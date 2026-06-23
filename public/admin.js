'use strict';

// Demande une confirmation avant toute suppression de participation.
(function () {
  document.querySelectorAll('.delete-form').forEach((form) => {
    form.addEventListener('submit', (event) => {
      if (!window.confirm('Supprimer definitivement cette participation ?')) {
        event.preventDefault();
      }
    });
  });
})();
