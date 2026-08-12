const button = document.getElementById("hop-button");
const countEl = document.getElementById("count");
const frog = document.getElementById("frog");

if (button && countEl && frog) {
  let hops = 0;

  button.addEventListener("click", () => {
    hops += 1;
    countEl.textContent = String(hops);

    // Restart the animation even on rapid clicks: remove the class, force a
    // reflow (reading offsetWidth flushes pending style changes), then
    // re-add it — without this, a second click before the first animation
    // finishes would be a no-op since the class never actually toggled off.
    frog.classList.remove("hop");
    void frog.offsetWidth;
    frog.classList.add("hop");
  });
}
