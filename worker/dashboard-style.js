export const themeScript = String.raw`
  (function () {
    var preference;
    try { preference = localStorage.getItem('dash-theme'); } catch (e) {}
    if (preference !== 'light' && preference !== 'dark') {
      var cookie = document.cookie.match(/(?:^|;\s*)dash-theme=(light|dark)(?:;|$)/);
      preference = cookie && cookie[1];
    }
    var system = matchMedia('(prefers-color-scheme: dark)');
    function apply() {
      var dark = preference ? preference === 'dark' : system.matches;
      document.documentElement.dataset.theme = dark ? 'dark' : 'light';
      var button = document.getElementById('themeToggle');
      if (button) button.setAttribute('aria-pressed', String(dark));
    }
    apply();
    system.addEventListener('change', apply);
    document.addEventListener('DOMContentLoaded', function () {
      apply();
      document.getElementById('themeToggle').addEventListener('click', function () {
        preference = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
        try { localStorage.setItem('dash-theme', preference); } catch (e) {}
        document.cookie = 'dash-theme=' + preference + '; Max-Age=31536000; Path=/; SameSite=Lax';
        apply();
      });
    });
  })();
`;

export const dashboardStyles = `
  :root {
    color-scheme: light;
    --bg:#f5f5ef; --surface:#fffefa; --text:#192920; --muted:#53645a; --line:#d9dfd5;
    --accent:#246644; --wash:#e9f0e6; --danger:#a22e2d;
    --warning:#805214; --warning-bg:#fcf1d7;
    --plot:#172e24; --plot-ink:#f4f8ed; --plot-muted:#b6c9ba; --lime:#d9f48c;
    --sans:"Avenir Next","Trebuchet MS",sans-serif;
    --display:Georgia,serif;
    --mono:ui-monospace,"SFMono-Regular",Consolas,monospace;
  }
  :root[data-theme=dark] {
    color-scheme:dark;
    --bg:#101914; --surface:#19251e; --text:#eff4e9; --muted:#b1c0b3; --line:#34443a;
    --accent:#a8dea8; --wash:#24372b; --danger:#ffada5;
    --warning:#ffda91; --warning-bg:#473519;
  }
  *,*::before,*::after { box-sizing:border-box }
  [hidden] { display:none !important }
  body { margin:0; background:var(--bg); color:var(--text); font: 500 1rem/1.5 var(--sans) }
  h1,h2,h3,p,ul,ol,dl,dd { margin:0 }
  h1,h2 { font:normal 2rem/1.12 var(--display); letter-spacing:-.035em }
  h1 { font-size:clamp(2.65rem,5vw,4.4rem) }
  h3 { font-size:1rem; line-height:1.35 }
  a { color:var(--accent); text-underline-offset:.22em; overflow-wrap:anywhere }
  a:hover { text-decoration-thickness:2px }
  :focus-visible { outline:2px solid var(--accent); outline-offset:3px }
  button,input,select { font:inherit }
  button { cursor:pointer }
  button:disabled { cursor:default; opacity:.56 }
  button:not(:disabled):hover { border-color:var(--accent) }
  .button,button:not(.chart-bar),.area-map-link {
    min-height:44px; display:inline-flex; align-items:center; justify-content:center; gap:.45rem;
    border:1px solid var(--line); border-radius:9px; background:var(--surface); color:var(--text);
    padding:.48rem .9rem; font-size:.86rem; font-weight:650; line-height:1.25; text-decoration:none
  }
  .button:hover,.area-map-link:hover { border-color:var(--accent) }
  .button.primary,button.primary,.identity-dialog .identity-confirm {
    border-color:var(--accent); background:var(--accent); color:var(--surface)
  }
  small,.muted,.identity-note { color:var(--muted); font-size:.85rem }
  .eyebrow { color:var(--accent); font:600 .73rem/1.5 var(--mono); letter-spacing:.1em; text-transform:uppercase }
  .sr-only {
    position:absolute; width:1px; height:1px; padding:0; margin:-1px;
    overflow:hidden; clip-path:inset(50%); white-space:nowrap; border:0
  }
  .skip-link:focus { position:fixed; z-index:3; top:.7rem; left:.7rem; width:auto; height:auto; margin:0; clip-path:none }
  .shell { width:min(100% - 4.5rem, 90rem); margin-inline:auto }
  .masthead { border-bottom:1px solid var(--line); background:var(--surface) }
  .masthead-inner,.brand,.top-actions,.navigation,.card-head,.section-head { display:flex; align-items:center }
  .masthead-inner { justify-content:space-between; gap:1rem; min-height:74px }
  .brand { gap:.7rem; font-weight:750; letter-spacing:-.03em; white-space:nowrap }
  .brand-mark {
    width:34px; height:34px; flex:none; display:flex; align-items:end; justify-content:center;
    gap:3px; padding:8px; background:var(--plot); border-radius:9px
  }
  .brand-mark i { width:3px; height:45%; background:var(--lime); border-radius:2px }
  .brand-mark i:nth-child(2) { height:72% }
  .brand-mark i:nth-child(3) { height:100% }
  .top-actions { gap:.45rem }
  .theme-icon { font-size:1.3rem; line-height:1 }
  #themeToggle { min-width:44px; padding:.5rem }
  .nav-shell { border-bottom:1px solid var(--line) }
  .navigation { gap:1.4rem }
  .navigation a { min-width:44px; text-align:center; padding:.75rem .18rem .7rem; min-height:48px; border-bottom:2px solid transparent; color:var(--muted); text-decoration:none; font-weight:650; font-size:.91rem }
  .navigation a:hover,.navigation a[aria-current] { color:var(--accent) }
  .navigation a[aria-current] { border-bottom-color:var(--accent) }
  main { padding-block:2.5rem 1.75rem; min-height:65vh }
  .section-head { justify-content:space-between; align-items:end; gap:1rem; margin-bottom:1.55rem }
  .section-head .eyebrow { margin-bottom:.42rem }
  .section-head .muted { margin-top:.4rem }
  .refresh-group { display:flex; align-items:center; gap:.7rem; flex-wrap:wrap }
  .refresh-status { color:var(--muted); font-size:.78rem; font-variant-numeric:tabular-nums }
  .refresh-status::before { content:''; display:inline-block; width:.48rem; height:.48rem; margin-right:.42rem; border-radius:50%; background:var(--accent); vertical-align:.08em }
  .refresh-status[data-error]::before { background:var(--danger) }
  .card,.metric,.profile-card {
    background:var(--surface); border:1px solid var(--line); border-radius:16px; min-width:0
  }
  .card { padding:clamp(1rem,2.5vw,1.6rem) }
  .card-head { justify-content:space-between; gap:.85rem; margin-bottom:1rem }
  .card-head > div { min-width:0 }
  .card-head .muted { margin-top:.35rem }
  .metrics { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:.9rem; margin-bottom:1rem }
  .metric { padding:.9rem 1.1rem; position:relative }
  .metric:first-child { border-top:3px solid var(--accent); padding-top:calc(.9rem - 2px) }
  .metric dt { color:var(--muted); font-size:.85rem; font-weight:650 }
  .metric-value { font:normal clamp(1.7rem,3vw,2.65rem)/1.22 var(--display); letter-spacing:-.045em; font-variant-numeric:lining-nums tabular-nums; margin:.25rem 0 .1rem; overflow-wrap:anywhere }
  .overview-grid { display:grid; grid-template-columns:minmax(0,1.8fr) minmax(0,1fr); align-items:stretch; gap:1rem; margin-bottom:1rem }
  .plot-card {
    background-color:var(--plot); border-color:#345043; color:var(--plot-ink);
    background-image:radial-gradient(ellipse at top right,#335441 0%,transparent 70%);
  }
  .plot-card .eyebrow,.plot-card :focus-visible { color:var(--lime); outline-color:var(--lime) }
  .plot-card .card-head { align-items:start; margin-bottom:1.2rem }
  .plot-card h2 { margin-top:.2rem }
  .periods { display:flex; flex:none; gap:.25rem }
  .plot-card .periods button { min-width:44px; padding:.3rem .55rem; background:transparent; color:var(--plot-ink); border-color:#6a8371; font-family:var(--mono) }
  .plot-card .periods button:is(:hover,[aria-pressed=true]) { color:var(--plot); background:var(--lime); border-color:var(--lime) }
  .plot-summary { display:flex; gap:.65rem; align-items:baseline; flex-wrap:wrap }
  .plot-total { color:var(--lime); font:normal 2.75rem/1 var(--display); font-variant-numeric:lining-nums tabular-nums }
  .plot-summary span:last-child,.plot-detail,.plot-dates { color:var(--plot-muted); font-size:.79rem }
  .plot-chart { position:relative; display:grid; grid-template-columns:2.25rem minmax(0,1fr); grid-template-rows:clamp(110px,14vw,175px) auto; column-gap:.55rem; margin-top:1rem }
  .plot-axis { display:flex; flex-direction:column; justify-content:space-between; text-align:right; color:var(--plot-muted); font: .69rem/1 var(--mono) }
  .plot-bars {
    display:grid; grid-template-columns:repeat(var(--days,30),minmax(0,1fr)); gap:clamp(1px,.28vw,5px); align-items:stretch;
    background-image:linear-gradient(to bottom,#536e5e 1px,transparent 1px),
                     linear-gradient(to bottom,transparent calc(50% - .5px),#536e5e calc(50% - .5px),#536e5e calc(50% + .5px),transparent calc(50% + .5px)),
                     linear-gradient(to top,#536e5e 1px,transparent 1px);
  }
  .chart-bar { display:flex; min-width:0; align-items:end; margin:0; padding:0; border:0; background:none; border-radius:3px }
  .chart-bar span { width:100%; height:max(2px,var(--height)); border-radius:3px 3px 0 0; background:#7da989; pointer-events:none }
  .chart-bar[data-active] span,.chart-bar:hover span,.chart-bar:focus-visible span { background:var(--lime) }
  .chart-bar:focus-visible { outline-offset:0 }
  .plot-dates { grid-column:2; display:flex; justify-content:space-between; margin-top:.5rem; font-family:var(--mono) }
  .plot-detail { min-height:1.4rem; margin-top:.65rem }
  .rank-list { list-style:none; padding:0; display:grid; gap:.8rem }
  .rank-list li { display:grid; grid-template-columns:2ch minmax(0,1fr) auto; gap:.15rem .65rem; align-items:baseline; font-size:.91rem }
  .rank-number,.rank-count { color:var(--muted); font: .76rem/1.3 var(--mono) }
  .rank-name { overflow-wrap:anywhere }
  .ref-bar { grid-column:2 / -1; background:var(--wash); height:4px; border-radius:4px; overflow:hidden }
  .ref-fill { height:100%; background:var(--accent); border-radius:inherit }
  .overview-country { align-self:start }
  .compact-visits { list-style:none; padding:0 }
  .compact-visits li { display:flex; align-items:center; justify-content:space-between; gap:.8rem; padding:.65rem 0; border-top:1px solid var(--line); overflow-wrap:anywhere }
  .compact-visits li > div { min-width:0 }
  .compact-visits small { display:block }
  .compact-visits time { white-space:nowrap; font-size:.8rem; color:var(--muted) }
  .favorite-alert { padding:.4rem .75rem; margin-bottom:1rem; border:1px solid var(--line); border-radius:10px; background:var(--wash); display:flex; align-items:center; gap:.5rem }
  .favorite-alert button { margin-left:auto; flex:none }
  .search-wrap input { width:100%; min-height:44px; padding:.5rem .75rem; color:var(--text); background:var(--bg); border:1px solid var(--line); border-radius:9px }
  .search-wrap input::placeholder { color:var(--muted) }
  .log-tools { display:flex; align-items:center; gap:.75rem; flex-wrap:wrap; margin-bottom:.7rem }
  .table-card:not(.is-managing) :is(.select-all,.sel-col,.act-col) { display:none }
  .manage-log[aria-pressed=true] { border-color:var(--accent); background:var(--wash); color:var(--accent) }
  .log-tools label,.identity-check { display:inline-flex; align-items:center; gap:.55rem; min-height:44px; cursor:pointer; font-size:.9rem }
  .chk,.identity-check input { width:1.1rem; height:1.1rem; margin:0; accent-color:var(--accent); flex:none }
  .bulkbar { display:flex; gap:.5rem; flex-wrap:wrap; align-items:center; padding:.45rem .65rem; background:var(--wash); border-radius:9px }
  .table-scroll-x { min-width:0 }
  table { border-collapse:collapse; width:100%; text-align:left; font-size:.86rem }
  th { color:var(--muted); font-weight:650; vertical-align:bottom; background:var(--bg) }
  th,td { padding:.65rem .55rem; border-bottom:1px solid var(--line); overflow-wrap:anywhere }
  td { vertical-align:middle }
  tbody tr:last-child td { border-bottom:0 }
  tbody tr:hover,.favorite-visit { background:var(--wash) }
  .sel-col,.act-col { width:1%; text-align:center }
  label.row-select { display:inline-grid; min-width:44px; min-height:44px; place-items:center; cursor:pointer }
  .badge { font: .74rem/1.3 var(--mono) }
  .location-meta,.click-action { display:flex; gap:.15rem .45rem; flex-wrap:wrap; align-items:center; margin-top:.1rem }
  .location-meta { color:var(--muted); font-size:.74rem }
  .area-map-link { padding:.2rem .4rem; border:0; color:var(--accent); background:none; font-size:.78rem; text-decoration:underline }
  .cell-secondary,.click-action small { display:block; color:var(--muted); font-size:.78rem }
  .click-action small { flex-basis:100%; font-family:var(--mono) }
  .click-quality,.prob { width:fit-content; padding:.13rem .4rem; border-radius:5px; background:var(--wash); color:var(--accent); font-size:.73rem }
  .click-quality-inferred,.prob-review { background:var(--warning-bg); color:var(--warning) }
  .click-quality-unknown,.click-quality-legacy { color:var(--muted) }
  .engagement-summary { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:.85rem; margin-bottom:1rem }
  .top-clicks { margin-bottom:1rem }
  .top-clicks ol { padding:0; list-style:none; display:flex; flex-wrap:wrap; gap:.5rem }
  .top-clicks li { padding:.35rem .55rem; border-radius:6px; background:var(--wash); overflow-wrap:anywhere }
  .top-clicks li strong { margin-left:.3rem; color:var(--accent) }
  .empty-state { color:var(--muted); padding:1rem .2rem; font-size:.9rem }
  .profile-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:.9rem }
  .profile-card { padding:1rem; display:flex; flex-direction:column; gap:.65rem; overflow-wrap:anywhere }
  .profile-card.is-favorite { border-color:var(--accent) }
  .profile-head { display:flex; gap:.5rem; justify-content:space-between; align-items:start }
  .profile-head .prob { flex:none }
  .profile-visits { color:var(--muted); font-size:.88rem }
  .profile-visits strong { color:var(--text) }
  .profile-meta,.identity-history { font-size:.84rem; color:var(--muted) }
  details > summary { width:fit-content; min-height:44px; padding:.64rem .2rem; cursor:pointer; font-weight:650; color:var(--accent) }
  .profile-meta dl { display:grid; grid-template-columns:auto minmax(0,1fr); gap:.25rem .6rem }
  .profile-meta dt { font-weight:650 }
  .profile-actions,.identity-members,.danger-actions { display:flex; flex-wrap:wrap; gap:.4rem }
  .profile-actions { margin-top:auto }
  .identity-chip { display:inline-flex; gap:.35rem; align-items:center; font: .78rem/1.4 var(--mono) }
  .identity-members { flex-direction:column; align-items:start }
  .identity-history { margin-top:1rem }
  .identity-history ul { padding-left:1.2rem }
  button.danger-btn,button.profile-delete,button.row-del { color:var(--danger) }
  .danger-zone { border-top:3px solid var(--danger); max-width:53rem }
  .danger-zone p { margin:.55rem 0 1rem; color:var(--muted) }
  .identity-dialog {
    width:min(94vw,35rem); max-height:88dvh; padding:clamp(1rem,4vw,1.65rem); border:1px solid var(--line);
    border-radius:16px; background:var(--surface); color:var(--text); box-shadow:0 24px 70px #07191155; overflow:auto
  }
  .identity-dialog::backdrop { background:#071911a8 }
  .identity-dialog p { margin:.55rem 0; color:var(--muted); font-size:.9rem }
  .identity-dialog label:not(.identity-check) { display:block; margin:.8rem 0 .35rem; font-size:.9rem; font-weight:650 }
  .identity-dialog select { width:100%; min-height:44px; padding:.5rem; border:1px solid var(--line); border-radius:8px; background:var(--bg); color:var(--text) }
  .identity-review { display:grid; grid-template-columns:1fr 1fr; gap:.5rem; margin-top:.9rem }
  .identity-review > div,.identity-signal,.visit-item,.visit-editor { padding:.7rem; background:var(--wash); border-radius:8px; font-size:.85rem; overflow-wrap:anywhere }
  .identity-review span { display:block; white-space:pre-line; margin-top:.25rem }
  .identity-signal,.visit-editor { margin-top:.7rem }
  .identity-warning { background:var(--warning-bg); color:var(--warning) }
  .identity-dialog .identity-error { color:var(--danger) }
  .identity-dialog-actions { display:flex; justify-content:end; flex-wrap:wrap; gap:.45rem; margin-top:1rem }
  .visit-list { display:grid; gap:.4rem; max-height:38vh; overflow:auto; margin-top:.7rem; padding:.2rem }
  .visit-item { display:flex; align-items:center; justify-content:space-between; gap:.6rem }
  .visit-item small { display:block }
  .visit-item button { flex:none }
  footer.shell { padding:1rem 0 1.45rem; border-top:1px solid var(--line); color:var(--muted); font-size:.78rem }
  .login-shell { min-height:calc(100dvh - 75px); display:grid; place-items:center; padding:1.4rem 0 }
  .login-card { width:min(100%,28rem); border-top:4px solid var(--accent); padding:clamp(1rem,5vw,2.2rem) }
  .login-card h1 { font-size:clamp(2rem,7vw,3.1rem); margin:.35rem 0 1.4rem }
  .login-card label { display:block; font-weight:650; margin-bottom:.35rem }
  .login-field { display:flex; gap:.4rem; margin-bottom:1rem }
  .login-field input { min-width:0; flex:1; padding:.56rem .65rem; border:1px solid var(--line); background:var(--bg); color:var(--text); border-radius:9px }
  .login-card .primary { width:100% }
  .login-error { color:var(--danger); margin-bottom:.7rem }
  .cf-turnstile { margin-bottom:.8rem; width:100% }
  @media(max-width:1000px) {
    .profile-grid { grid-template-columns:repeat(2,minmax(0,1fr)) }
    th,td { padding:.5rem .35rem }
  }
  @media(max-width:850px) {
    .shell { width:calc(100% - 2rem) }
    .overview-grid { grid-template-columns:minmax(0,1.5fr) minmax(0,1fr) }
    .log-table thead { position:absolute; width:1px; height:1px; overflow:hidden; clip-path:inset(50%) }
    .log-table,.log-table tbody { display:block }
    .log-table tr { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:.55rem 1rem; border-top:1px solid var(--line); padding:.75rem 0 }
    .log-table tr:hover { background:transparent }
    .log-table td { display:block; border:0; padding:0; width:auto }
    .log-table td[data-label]::before { content:attr(data-label); display:block; color:var(--muted); font-size:.72rem; font-weight:650; margin-bottom:.15rem }
    .log-table td.time-cell { grid-column:1 / -1; grid-row:1; font-weight:650 }
    .log-table td.main-cell,.log-table td.empty-state { grid-column:1 / -1 }
    .log-table td.main-cell { grid-row:2 }
    .log-table td.sel-col,.log-table td.act-col { grid-row:5; text-align:left }
    .log-table td.act-col { text-align:right }
    #clickTbody td:is(.sel-col,.act-col) { grid-row:6 }
    .log-table tr.favorite-visit { border-left:3px solid var(--accent); padding-left:.55rem }
  }
  @media(max-width:620px) {
    main { padding-top:1.45rem }
    .masthead-inner { min-height:62px }
    .navigation { justify-content:space-between; gap:.25rem }
    .navigation a { font-size:.8rem; padding-inline:.1rem }
    .section-head { align-items:start; flex-direction:column; gap:.7rem; margin-bottom:1rem }
    .metrics { grid-template-columns:repeat(2,minmax(0,1fr)); gap:.55rem }
    .metric { padding:.65rem .7rem }
    .metric:first-child { padding-top:calc(.65rem - 2px) }
    .engagement-summary { grid-template-columns:repeat(2,minmax(0,1fr)); gap:.55rem }
    .overview-grid,.profile-grid { grid-template-columns:minmax(0,1fr); gap:.75rem }
    .card-head:has(.search-wrap) { align-items:stretch; flex-direction:column }
    .table-card { padding:.9rem }
  }
  @media(max-width:370px) {
    .shell { width:calc(100% - 1.25rem) }
    .navigation a { font-size:.75rem }
    .identity-review { grid-template-columns:1fr }
    .plot-card h2 { font-size:1.65rem }
  }
`;
