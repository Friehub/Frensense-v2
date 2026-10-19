export function render(el: HTMLElement) {
  el.textContent = location.hash.slice(1);
}
