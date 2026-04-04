/* WTFpkg — Main JS */

// --- Theme Toggle ---
(function() {
  var toggle = document.getElementById('theme-toggle');
  var icon = toggle && toggle.querySelector('.theme-icon');
  if (!toggle) return;

  function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('wtfpkg-theme', theme);
    icon.textContent = theme === 'dark' ? '\u263E' : '\u2600';
  }

  var current = document.documentElement.getAttribute('data-theme') || 'dark';
  icon.textContent = current === 'dark' ? '\u263E' : '\u2600';

  toggle.addEventListener('click', function() {
    var cur = document.documentElement.getAttribute('data-theme');
    setTheme(cur === 'dark' ? 'light' : 'dark');
  });
})();

// --- Copy to Clipboard ---
document.addEventListener('click', function(e) {
  var btn = e.target.closest('.copy-btn');
  if (!btn) return;

  var wrapper = btn.closest('.code-block-wrapper');
  var code = wrapper && wrapper.querySelector('code');
  if (!code) return;

  navigator.clipboard.writeText(code.textContent).then(function() {
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(function() {
      btn.textContent = 'Copy';
      btn.classList.remove('copied');
    }, 1500);
  });
});

// --- Technique Grid Search & Filter (drill-down pages) ---
(function() {
  var searchInput = document.getElementById('technique-search');
  var catFilter = document.getElementById('filter-category');
  var sevFilter = document.getElementById('filter-severity');
  var resultsCount = document.getElementById('results-count');
  var noResults = document.getElementById('no-results');
  var grid = document.getElementById('technique-grid');

  if (!searchInput || !grid) return;

  var cards = Array.from(grid.querySelectorAll('.technique-card'));
  var total = cards.length;

  function applyFilters() {
    var query = searchInput.value.toLowerCase().trim();
    var cat = catFilter.value;
    var sev = sevFilter.value;
    var visible = 0;

    cards.forEach(function(card) {
      var name = (card.dataset.name || '').toLowerCase();
      var desc = (card.dataset.description || '').toLowerCase();
      var cardCat = card.dataset.category || '';
      var cardSev = card.dataset.severity || '';

      var match = (!query || name.includes(query) || desc.includes(query))
        && (!cat || cardCat === cat)
        && (!sev || cardSev === sev);

      card.classList.toggle('hidden', !match);
      if (match) visible++;
    });

    resultsCount.textContent = visible + '/' + total;

    if (noResults) {
      noResults.style.display = visible === 0 ? '' : 'none';
      grid.style.display = visible === 0 ? 'none' : '';
    }
  }

  searchInput.addEventListener('input', applyFilters);
  catFilter.addEventListener('change', applyFilters);
  sevFilter.addEventListener('change', applyFilters);
  resultsCount.textContent = total + '/' + total;
})();

// --- Back to Top ---
(function() {
  var btn = document.getElementById('back-to-top');
  if (!btn) return;

  window.addEventListener('scroll', function() {
    btn.classList.toggle('visible', window.scrollY > 400);
  }, { passive: true });

  btn.addEventListener('click', function() {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
})();
