/* Petit script commun à toutes les pages : l'horloge de l'en-tête. */
"use strict";

(function startClock() {
  const clock = document.getElementById("clock");
  if (!clock) return;
  const tick = () => {
    clock.textContent = new Date().toLocaleString("fr-FR", {
      weekday: "short", day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
  };
  tick();
  setInterval(tick, 1000);
})();
