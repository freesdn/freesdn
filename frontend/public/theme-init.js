(function () {
  try {
    var raw = localStorage.getItem('freesdn-ui-settings');
    if (raw) {
      var parsed = JSON.parse(raw);
      var theme = parsed && parsed.state && parsed.state.theme;
      if (theme === 'dark') {
        document.documentElement.classList.add('dark');
      } else if (theme === 'system') {
        if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
          document.documentElement.classList.add('dark');
        }
      }
    } else {
      // Default to dark (matches useUIStore initial state)
      document.documentElement.classList.add('dark');
    }
  } catch (e) {
    document.documentElement.classList.add('dark');
  }
})();
