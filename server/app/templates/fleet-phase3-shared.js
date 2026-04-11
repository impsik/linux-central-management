(function (w) {
  function formatDateSafe(value) {
    if (!value) return '–';
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString();
  }

  function callOptional(ctx, name, fallback, ...args) {
    if (ctx && typeof ctx[name] === 'function') return ctx[name](...args);
    return typeof fallback === 'function' ? fallback(...args) : fallback;
  }

  function formatShortTimeSafe(ctx, value) {
    return callOptional(ctx, 'formatShortTime', () => {
      if (typeof w.formatShortTime === 'function') return w.formatShortTime(value);
      return formatDateSafe(value);
    }, value);
  }

  function getCtxString(ctx, name, fallback = '') {
    const val = callOptional(ctx, name, fallback);
    return String(val || '').trim();
  }

  w.phase3Shared = {
    formatDateSafe,
    callOptional,
    formatShortTimeSafe,
    getCtxString,
  };
})(window);
