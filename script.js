document.querySelectorAll('.copy-button').forEach((button) => {
  button.addEventListener('click', async () => {
    const original = button.textContent;
    try {
      await navigator.clipboard.writeText(button.dataset.copy);
      button.textContent = 'copied';
      setTimeout(() => { button.textContent = original; }, 1600);
    } catch {
      button.textContent = 'select manually';
      setTimeout(() => { button.textContent = original; }, 1600);
    }
  });
});
