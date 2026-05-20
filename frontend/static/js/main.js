// AegisGraph — Frontend JS utilities

// Auto-highlight active nav
document.querySelectorAll('.nav-item').forEach(el => {
  if (el.href === window.location.href) el.classList.add('active');
});

// Vuln card expand toggle (fallback if inline onclick fails)
document.querySelectorAll('.vuln-card').forEach(card => {
  card.addEventListener('click', () => card.classList.toggle('expanded'));
});
