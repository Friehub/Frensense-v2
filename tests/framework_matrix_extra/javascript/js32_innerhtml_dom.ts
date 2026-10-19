export function render(el: HTMLElement) {
  el.innerHTML = location.hash.slice(1);
}
