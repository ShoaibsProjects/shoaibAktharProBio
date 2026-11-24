export const DASHBOARD_CLIENT_JS = String.raw`
  var number = new Intl.NumberFormat('en-US');
  var central = new Intl.DateTimeFormat('en-US', {month:'short', day:'numeric', hour:'numeric', minute:'2-digit', timeZone:'America/Chicago'});
  var dayFormat = new Intl.DateTimeFormat('en-US', {month:'short', day:'numeric', timeZone:'UTC'});
  var _sd = window.__DASH;
  var selectedDays = 30;
  var selectedDay = '';
  var rendered = new Map();

  function el(id) { return document.getElementById(id); }
  function escH(value) {
    return String(value).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
  function fmtH(time) { return time ? central.format(new Date(time + 'Z')) : ''; }
  function device(v) {
    return [v.device_type, v.os, v.browser].filter(function(value) { return value && value !== 'Unknown'; }).join(' · ') || 'Unknown device';
  }
  function area(v) { return [v.city, v.region, v.country].filter(Boolean).join(', '); }
  function locationCell(v) {
    var place = area(v);
    if (!place) return v.latitude != null || v.longitude != null
      ? 'Approximate area <small class="cell-secondary">IP-based estimate · Place name unavailable</small>' : '—';
    return escH(place) + '<div class="location-meta"><span>IP-based estimate</span><a class="area-map-link" href="https://maps.apple.com/?q='
      + encodeURIComponent(place) + '" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer" aria-label="Open the approximate area in Apple Maps">Apple Maps ↗</a></div>';
  }
  function linkCell(url, showPath) {
    if (!url || !/^https?:\/\//i.test(url)) return '—';
    var label;
    try {
      var parsed = new URL(url);
      label = parsed.hostname + (showPath && parsed.pathname !== '/' ? parsed.pathname : '');
      if (label.length > 75) label = label.slice(0, 74) + '…';
    } catch (e) { return '—'; }
    return '<a href="' + escH(url) + '" title="' + escH(url) + '" target="_blank" rel="noopener noreferrer">' + escH(label) + '</a>';
  }
  function profileCell(row, id) {
    return id ? '<span class="badge" title="Original ID: ' + escH(row.visitor_id || '') + '">' + escH(id.slice(0, 8)) + '</span>' : '—';
  }
  function cell(label, content, className) {
    return '<td role="cell" data-label="' + label + '"' + (className ? ' class="' + className + '"' : '') + '>' + content + '</td>';
  }
  function rowControls(row, kind, selected) {
    var id = escH(String(row.id));
    var visit = kind === 'visit';
    var label = visit ? 'visit' : 'interaction';
    return {
      select:'<td role="cell" class="sel-col"><label class="row-select"><input type="checkbox" class="chk row-chk" data-id="' + id + '" aria-label="Select ' + label + ' ' + id + '"' + (selected.has(String(row.id)) ? ' checked' : '') + '></label></td>',
      remove:'<td role="cell" class="act-col"><button type="button" class="row-del" data-kind="' + kind + '" data-id="' + id + '" aria-label="Delete ' + label + ' ' + id + '">Delete</button></td>'
    };
  }
  function rowHtml(row, selected) {
    var id = row.profile_id || row.visitor_id || '';
    var controls = rowControls(row, 'visit', selected);
    return '<tr role="row" data-vid="' + escH(id) + '">' + controls.select
      + cell('Time (Central)', fmtH(row.created_at), 'time-cell')
      + cell('Approx. area', locationCell(row), 'main-cell')
      + cell('Device', escH(device(row)))
      + cell('Source', row.referrer ? linkCell(row.referrer) : 'Direct')
      + cell('Profile', profileCell(row, id)) + controls.remove + '</tr>';
  }
  function clickRowHtml(row, selected) {
    var id = row.profile_id || row.visitor_id || '';
    var controls = rowControls(row, 'engagement', selected);
    var quality = ['named','inferred','unknown'].includes(row.label_quality) ? row.label_quality : 'legacy';
    var raw = row.target || '';
    var label = quality === 'legacy' && /^(div|span|svg)(#|\[|\s)/i.test(raw) ? 'Unverified page element' : raw || 'Unidentified click';
    var qualityLabel = { named:'Named control', inferred:'Inferred control', unknown:'Unidentified', legacy:'Earlier format' }[quality];
    var detail = row.action_id || (raw !== label && raw) || {site:'Your site','site-widget':'Gallery widget',outside:'Outside site content'}[row.source];
    var action = '<div class="click-action"><strong>' + escH(label) + '</strong><span class="click-quality click-quality-' + quality + '">' + qualityLabel + '</span>'
      + (detail ? '<small>' + escH(detail) + '</small>' : '') + '</div>';
    var pos = row.interaction === 'non-pointer' ? 'Non-pointer' : row.x != null && row.y != null ? row.x + ', ' + row.y : '—';
    if (row.viewport_w && row.viewport_h) pos += '<small class="cell-secondary">' + row.viewport_w + ' × ' + row.viewport_h + ' viewport</small>';
    return '<tr role="row" data-vid="' + escH(id) + '">' + controls.select
      + cell('Time (Central)', fmtH(row.created_at), 'time-cell')
      + cell('Interaction', action, 'main-cell')
      + cell('Approx. area', locationCell(row))
      + cell('Section', escH(row.section || '—'))
      + cell('Destination', linkCell(row.href, true))
      + cell('Profile', profileCell(row, id))
      + cell('Position', pos) + controls.remove + '</tr>';
  }

  function query(id) { return el(id).value.trim().toLowerCase(); }
  function matches(parts, value) { return !value || parts.filter(Boolean).join(' ').toLowerCase().includes(value); }

  function renderLog(kind) {
    var recent = kind === 'recent';
    var tbody = el(kind + 'Tbody');
    var search = query(kind + 'Search');
    var rows = recent ? _sd.recent : _sd.engagement.clickDetails;
    var next = JSON.stringify([search, rows]);
    if (rendered.get(kind) === next) return;
    rendered.set(kind, next);
    var selected = new Set(selectedIds(tbody.id));
    var shown = rows.filter(function(row) {
      var parts = [row.city,row.region,row.country,row.visitor_id,row.profile_id];
      return matches(parts.concat(recent
        ? [row.device_type,row.os,row.browser,row.isp,row.postal_code,row.referrer]
        : [row.section,row.target,row.action_id,row.label_quality,row.href]), search);
    });
    var template = recent ? rowHtml : clickRowHtml;
    var message = search ? 'No matches. Try a different search.' : recent ? 'No visits recorded yet.' : 'No interactions recorded yet.';
    tbody.innerHTML = shown.length ? shown.map(function(row) { return template(row, selected); }).join('')
      : '<tr role="row"><td role="cell" colspan="' + (recent ? 7 : 9) + '" class="empty-state">' + message + '</td></tr>';
    updateBulkBar(kind);
    applyFavorites();
  }

  function rankList(target, rows, empty) {
    var max = rows.length ? Math.max(1, ...rows.map(function(row) { return row.count; })) : 1;
    el(target).innerHTML = rows.length ? rows.map(function(row, i) {
      return '<li><span class="rank-number" aria-hidden="true">' + (i + 1) + '</span><span class="rank-name">' + escH(row.name)
        + '</span><strong class="rank-count">' + number.format(row.count) + '</strong>'
        + '<div class="ref-bar" aria-hidden="true"><div class="ref-fill" style="width:' + row.count / max * 100 + '%"></div></div></li>';
    }).join('') : '<li class="empty-state">' + empty + '</li>';
  }

  function plotDay(button, focus) {
    var current = el('plotBars').querySelector('[data-active]');
    if (current) { current.removeAttribute('data-active'); current.tabIndex = -1; }
    button.dataset.active = '';
    button.tabIndex = 0;
    selectedDay = button.dataset.date;
    el('plotDetail').textContent = button.getAttribute('aria-label');
    if (focus) button.focus();
  }
  function renderChart() {
    var today = new Date();
    var points = new Map(_sd.trend.map(function(point) { return [point.date, point.count]; }));
    var days = Array.from({length:selectedDays}, function(_, i) {
      var date = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() - selectedDays + 1 + i));
      var key = date.toISOString().slice(0, 10);
      return {key:key, label:dayFormat.format(date), count:points.get(key) || 0};
    });
    var signature = JSON.stringify(days);
    if (rendered.get('plot') === signature) return;
    rendered.set('plot', signature);
    var peak = Math.max(1, ...days.map(function(day) { return day.count; }));
    var step = Math.pow(10, Math.floor(Math.log10(peak)));
    var max = Math.max(2, Math.ceil(peak / (step * 2)) * step * 2);
    var total = days.reduce(function(sum, day) { return sum + day.count; }, 0);
    el('plotTotal').textContent = number.format(total);
    el('plotSummary').textContent = (total === 1 ? 'view' : 'views') + ' in ' + selectedDays + ' days';
    el('plotAxis').innerHTML = [max, max / 2, 0].map(function(tick) { return '<span>' + number.format(tick) + '</span>'; }).join('');
    var bars = el('plotBars');
    var focused = bars.contains(document.activeElement);
    bars.style.setProperty('--days', selectedDays);
    bars.innerHTML = days.map(function(day) {
      return '<button class="chart-bar" type="button" tabindex="-1" data-date="' + day.key + '" aria-label="'
        + day.label + ' · ' + number.format(day.count) + (day.count === 1 ? ' view' : ' views') + '"><span style="--height:' + (day.count / max * 100) + '%"></span></button>';
    }).join('');
    el('plotDates').innerHTML = '<span>' + days[0].label + '</span><span>' + days[days.length - 1].label + '</span>';
    plotDay(bars.querySelector('[data-date="' + selectedDay + '"]') || bars.lastElementChild, focused);
  }

  function profileName(profile) {
    return profile.oss.length > 1 && profile.countries.length > 1 ? 'Mixed device signals'
      : [profile.oss[0],profile.browsers[0],profile.cities[0]].filter(function(value) { return value && value !== 'Unknown'; }).join(' · ') || 'Unknown device';
  }
  function renderProfiles() {
    var search = query('profileSearch');
    var onlySaved = el('savedProfiles').checked;
    var favorites = getFavorites();
    var next = JSON.stringify([_sd.profiles, search, onlySaved, favorites]);
    if (rendered.get('profiles') === next) return;
    rendered.set('profiles', next);
    var grid = el('profileGrid');
    var expanded = new Set(Array.from(grid.querySelectorAll('details[open]'), function(details) { return details.closest('[data-vid]').dataset.vid; }));
    var focus = document.activeElement;
    var focusCard = grid.contains(focus) ? focus.closest('.profile-card') : null;
    var profiles = _sd.profiles.filter(function(p) {
      return (!onlySaved || favorites.includes(p.id)) && matches([p.id,profileName(p)].concat(p.members,p.cities,p.countries,p.devices,p.oss,p.browsers), search);
    }).sort(function(a, b) { return Number(favorites.includes(b.id)) - Number(favorites.includes(a.id)); });
    grid.innerHTML = profiles.length ? profiles.map(function(p) {
      var id = escH(p.id);
      var saved = favorites.includes(p.id);
      var title = profileName(p);
      var details = [
        ['First visit', fmtH(p.firstSeen)],
        ['Areas', p.cities.concat(p.countries).join(', ')],
        ['Networks', p.isps.join(', ')],
        ['Network IDs', p.ipHashes.map(function(hash) { return hash.slice(0, 8); }).join(', ')],
        ['Time zones', p.timezones.join(', ')]
      ].filter(function(pair) { return pair[1]; }).map(function(pair) { return '<dt>' + pair[0] + '</dt><dd>' + escH(pair[1]) + '</dd>'; }).join('');
      var members = p.members.length > 1 ? '<div class="identity-members"><strong>Linked IDs</strong>' + p.members.map(function(member) {
        return '<span class="identity-chip" title="' + escH(member) + '">' + escH(member.slice(0, 10)) + (member !== p.id
          ? ' <button type="button" class="profile-separate" data-member="' + escH(member) + '" data-canonical="' + id + '" aria-label="Unlink ' + escH(member) + '">Unlink</button>' : '') + '</span>';
      }).join('') + '</div>' : '';
      return '<article class="profile-card' + (saved ? ' is-favorite' : '') + '" data-vid="' + id + '">'
        + '<header class="profile-head"><h3 class="profile-name">' + escH(title) + '</h3>' + (title === 'Mixed device signals' ? '<span class="prob prob-review">Review</span>' : '') + '</header>'
        + '<span class="badge" title="' + id + '">' + escH(p.id.slice(0, 10)) + '</span>'
        + '<p class="profile-visits"><strong>' + number.format(p.visits) + (p.visits === 1 ? ' visit' : ' visits') + '</strong>' + (p.lastSeen ? ' · Last seen ' + fmtH(p.lastSeen) : '') + '</p>'
        + '<details class="profile-meta"' + (expanded.has(p.id) ? ' open' : '') + '><summary>Profile details</summary><dl>' + details + '</dl>' + members + '</details>'
        + '<div class="profile-actions"><button type="button" class="favorite-btn" aria-pressed="' + saved + '" data-vid="' + id + '">' + (saved ? '★ Saved' : '☆ Save') + '</button>'
        + '<button type="button" class="profile-review" data-vid="' + id + '">Review visits</button>'
        + '<button type="button" class="profile-merge" data-vid="' + id + '">Combine</button>'
        + '<button type="button" class="profile-delete" data-vid="' + id + '">Delete</button></div></article>';
    }).join('') : '<p class="empty-state">' + (search || onlySaved ? 'No profiles match these filters.' : 'No visitor profiles yet.') + '</p>';
    if (focusCard) {
      var card = Array.from(grid.children).find(function(item) { return item.dataset.vid === focusCard.dataset.vid; });
      var replacement = card && (focus.className ? Array.from(card.querySelectorAll('button')).find(function(button) {
        return button.className === focus.className && button.dataset.member === focus.dataset.member;
      }) : card.querySelector('summary'));
      (replacement || el('profileSearch')).focus({preventScroll:true});
    }
  }

  function renderHistory() {
    var next = JSON.stringify(_sd.identityEvents);
    if (rendered.get('history') === next) return;
    rendered.set('history', next);
    el('identityHistory').innerHTML = _sd.identityEvents.length ? '<ul>' + _sd.identityEvents.map(function(event) {
      var summary = event.action === 'merge' ? 'Combined ' + event.affected.length + (event.affected.length === 1 ? ' ID' : ' IDs')
        : event.action === 'separate' ? 'Unlinked an ID' : (event.action === 'move' ? 'Moved' : 'Restored') + ' visit #' + event.viewId;
      return '<li>' + fmtH(event.createdAt) + ' · ' + summary + (event.target ? ' → ' + escH(event.target.slice(0, 10)) : '') + '</li>';
    }).join('') + '</ul>' : '<p class="empty-state">No identity changes yet.</p>';
  }

  function renderDashboardData() {
    var t = _sd.totals, engagement = _sd.engagement;
    var seconds = engagement.avgDurationSec || 0;
    var minutes = Math.floor(seconds / 60);
    var hours = Math.floor(minutes / 60);
    var duration = hours ? hours + 'h' + (minutes % 60 ? ' ' + (minutes % 60) + 'm' : '')
      : minutes ? minutes + 'm' + (seconds % 60 ? ' ' + (seconds % 60) + 's' : '') : seconds + 's';
    var values = {statToday:t.today, stat24h:t.last24h, statTotal:t.total, statUnique:t.unique,
      statClicks:engagement.totalClicks, statSessions:engagement.sessions, statAvg:duration};
    Object.entries(values).forEach(function(pair) {
      el(pair[0]).textContent = typeof pair[1] === 'number' ? number.format(pair[1]) : pair[1];
    });
    renderChart();
    rankList('refList', _sd.referrers.map(function(r) { return {name:r.source,count:r.count}; }), 'No traffic sources yet.');
    var regions = typeof Intl.DisplayNames === 'function' ? new Intl.DisplayNames(['en'], {type:'region'}) : null;
    rankList('countryList', _sd.topCountries.map(function(r) {
      return {name:regions && /^[A-Z]{2}$/.test(r.country) ? regions.of(r.country) : r.country,count:r.count};
    }), 'No country data yet.');
    var latest = el('latestVisits');
    latest.innerHTML = _sd.recent.length ? _sd.recent.slice(0, 5).map(function(v) {
      var when = v.created_at ? '<time datetime="' + escH(v.created_at.replace(' ', 'T')) + 'Z">' + fmtH(v.created_at) + '</time>' : '';
      return '<li><div><strong>' + escH(area(v) || 'Unknown area') + '</strong><small>' + escH(device(v)) + '</small></div>' + when + '</li>';
    }).join('') : '<li class="empty-state">No visits recorded yet.</li>';
    el('topClickList').innerHTML = engagement.topClicks.length ? engagement.topClicks.slice(0, 5).map(function(click) {
      var name = !click.label_quality && /^(div|span|svg)(#|\[|\s)/i.test(click.target) ? 'Unverified element' : click.target;
      return '<li>' + escH(name) + ' <strong>' + number.format(click.count) + '</strong></li>';
    }).join('') : '<li class="empty-state">No clicks recorded yet.</li>';
    renderLog('recent');
    renderLog('click');
    renderProfiles();
    renderHistory();
    showFavoriteAlert();
  }

  function selectView(moveFocus) {
    var views = Array.from(document.querySelectorAll('[data-view]'));
    var active = views.find(function(view) { return '#' + view.id === location.hash; }) || views[0];
    views.forEach(function(view) { view.hidden = view !== active; });
    el('dashboardNav').querySelectorAll('a').forEach(function(link) {
      if (link.hash === '#' + active.id) link.setAttribute('aria-current','page');
      else link.removeAttribute('aria-current');
    });
    if (moveFocus && location.hash !== '#dashboardMain') {
      active.querySelector('h1').focus({preventScroll:true});
      window.scrollTo(0, 0);
    }
  }

  var refreshing = false;
  async function refresh(manual) {
    if (refreshing) return;
    refreshing = true;
    var status = el('refreshStatus');
    var button = el('refreshButton');
    button.disabled = true;
    if (manual) status.textContent = 'Refreshing…';
    try {
      var response = await fetch('/stats', {headers:{Accept:'application/json'}});
      if (response.status === 401) { location.href = '/dashboard'; return; }
      if (!response.ok) throw new Error('Refresh failed');
      var data = await response.json();
      // A periodic refresh must not replace a focused log control during review or selection.
      if (!manual && (document.activeElement.closest('tbody, .profile-card') || document.querySelector('dialog[open]'))) return;
      _sd = data;
      renderDashboardData();
      status.removeAttribute('data-error');
      status.textContent = 'Updated ' + new Date().toLocaleTimeString('en-US',{hour:'numeric',minute:'2-digit',timeZone:'America/Chicago'});
    } catch (e) {
      status.dataset.error = '';
      status.textContent = 'Refresh failed. Try again.';
    } finally {
      button.disabled = false;
      refreshing = false;
    }
  }
  el('refreshButton').addEventListener('click', function() { refresh(true); });
  setInterval(function() { if (!document.hidden && !document.querySelector('dialog[open]')) refresh(false); }, 60000);
  window.addEventListener('hashchange', function() { selectView(true); });
  document.querySelector('.skip-link').addEventListener('click', function(e) {
    e.preventDefault();
    el('dashboardMain').focus();
  });
  document.querySelectorAll('.manage-log').forEach(function(button) {
    button.addEventListener('click', function() {
      var card = button.closest('.table-card');
      var enabled = card.classList.toggle('is-managing');
      button.setAttribute('aria-pressed', String(enabled));
      if (enabled) return;
      var tbody = card.querySelector('tbody');
      tbody.querySelectorAll('.row-chk:checked').forEach(function(input) { input.checked = false; });
      updateBulkBar(tbody.id === 'recentTbody' ? 'recent' : 'click');
    });
  });
  el('recentSearch').addEventListener('input', function() { renderLog('recent'); });
  el('clickSearch').addEventListener('input', function() { renderLog('click'); });
  el('profileSearch').addEventListener('input', renderProfiles);
  el('savedProfiles').addEventListener('change', renderProfiles);

  document.querySelectorAll('[data-days]').forEach(function(button) {
    button.addEventListener('click', function() {
      selectedDays = Number(button.dataset.days);
      document.querySelectorAll('[data-days]').forEach(function(option) { option.setAttribute('aria-pressed', String(option === button)); });
      renderChart();
    });
  });
  var chart = el('plotBars');
  chart.addEventListener('pointerover', function(e) {
    if (e.pointerType === 'mouse' && e.target.matches('.chart-bar') && !chart.contains(document.activeElement)) plotDay(e.target, false);
  });
  chart.addEventListener('click', function(e) {
    if (e.target.matches('.chart-bar')) plotDay(e.target, true);
  });
  chart.addEventListener('keydown', function(e) {
    var button = e.target;
    if (!button.matches('.chart-bar')) return;
    var next = { ArrowLeft:button.previousElementSibling, ArrowRight:button.nextElementSibling,
      Home:chart.firstElementChild, End:chart.lastElementChild };
    if (!(e.key in next)) return;
    e.preventDefault();
    if (next[e.key]) plotDay(next[e.key], true);
  });

  var identityDialog=document.getElementById('identityDialog');
  var identityState=null;
  function identityProfile(id){return ((_sd&&_sd.profiles)||[]).find(function(p){return p.id===id;});}
  function identitySummary(p){return p?((p.oss||[]).concat(p.browsers||[]).concat(p.cities||[]).filter(Boolean).slice(0,3).join(' · ')||'Unknown device')+' · '+p.visits+' visits · '+p.members.length+' ID'+(p.members.length===1?'':'s'):'No visits';}
  function sharedSignal(a,b,key){return (a[key]||[]).some(function(x){return (b[key]||[]).indexOf(x)>=0;});}
  function identityReview(){
    if(!identityState)return;
    var keep=identityState.source,add=identityState.action==='merge'?document.getElementById('identityTarget').value:identityState.target;
    var left=identityProfile(keep),right=identityProfile(add);
    document.getElementById('identityFrom').textContent=identityState.action==='merge'?keep+'\n'+identitySummary(left):keep;
    document.getElementById('identityTo').textContent=add?add+'\n'+identitySummary(right):'Choose a second profile above';
    if(identityState.action==='merge'){
      var differentCountry=left&&right&&left.countries.length&&right.countries.length&&!sharedSignal(left,right,'countries');
      var differentDevice=left&&right&&left.oss.length&&right.oss.length&&!sharedSignal(left,right,'oss');
      var signal=document.getElementById('identitySignals');
      signal.textContent=!add?'Choose a second profile to compare.':differentCountry&&differentDevice?'Caution: these profiles show different countries and devices. Review visits before combining.':differentCountry?'Caution: the countries differ. Location alone is not proof they are different people.':differentDevice?'Caution: the devices differ. A person may use more than one device.':'Device and location clues can help, but they do not prove two profiles are the same person.';
      signal.classList.toggle('identity-warning',!!(differentCountry||differentDevice));
      document.getElementById('identityOutcome').textContent=left&&right?'After combining: one profile with '+(left.visits+right.visits)+' visits. The visitor count drops by one; original visits and clicks are unchanged. '+(right.members.length>1?'This adds '+right.members.length+' IDs; undo by unlinking each added ID.':'You can undo by clicking Unlink on the added ID.') :'';
      document.getElementById('identityApproval').disabled=!add;
      if(!add)document.getElementById('identityApproval').checked=false;
      document.getElementById('identityConfirm').disabled=!add||!document.getElementById('identityApproval').checked;
    }else document.getElementById('identityConfirm').disabled=false;
  }
  function identityOpen(action,source,target){
    if(!identityDialog)return;
    identityState={action:action,source:source,target:target||''};
    var select=document.getElementById('identityTarget');
    var wrap=document.getElementById('identityTargetWrap');
    var confirm=document.getElementById('identityConfirm');
    var err=document.getElementById('identityError');
    err.hidden=true;err.textContent='';
    document.getElementById('identityApproval').checked=false;
    select.innerHTML='';
    if(action==='merge'){
      wrap.hidden=false;
      var placeholder=document.createElement('option');placeholder.value='';placeholder.textContent='Select a profile to add…';placeholder.disabled=true;placeholder.selected=true;select.appendChild(placeholder);
      ((_sd&&_sd.profiles)||[]).filter(function(p){return p.id!==source;}).forEach(function(p){var o=document.createElement('option');o.value=p.id;o.textContent=p.id.slice(0,10)+' · '+identitySummary(p);select.appendChild(o);});
      document.getElementById('identityDialogTitle').textContent='Are these the same person?';
      document.getElementById('identityDialogDescription').textContent='This profile stays as the main card. Choose a second profile to add only when you recognize both as the same person. To separate people already mixed in one card, use Review visits instead.';
      document.getElementById('identityFromLabel').textContent='Keep this profile';
      document.getElementById('identityToLabel').textContent='Add this profile';
      document.getElementById('identitySignals').hidden=false;
      document.getElementById('identityOutcome').hidden=false;
      document.getElementById('identityApprovalWrap').hidden=false;
      confirm.textContent='Combine into this profile';confirm.disabled=true;
      if(select.options.length===1){err.textContent='There are no other profiles to combine.';err.hidden=false;}
    }else{
      wrap.hidden=true;
      document.getElementById('identityDialogTitle').textContent='Unlink visitor ID';
      document.getElementById('identityDialogDescription').textContent='This only removes a recent profile link. It cannot split older visits that were stored with the same ID; use Review visits for those.';
      document.getElementById('identityFromLabel').textContent='ID to unlink';
      document.getElementById('identityToLabel').textContent='Current profile';
      document.getElementById('identitySignals').hidden=true;
      document.getElementById('identityOutcome').hidden=true;
      document.getElementById('identityApprovalWrap').hidden=true;
      confirm.textContent='Unlink ID';confirm.disabled=false;
    }
    identityReview();identityDialog.showModal();
  }
  if(identityDialog){
    document.getElementById('identityTarget').addEventListener('change',function(){document.getElementById('identityApproval').checked=false;identityReview();});
    document.getElementById('identityApproval').addEventListener('change',identityReview);
    document.getElementById('identityCancel').addEventListener('click',function(){identityDialog.close();});
    document.getElementById('identityConfirm').addEventListener('click',function(){
      if(!identityState)return;
      var confirm=this,err=document.getElementById('identityError');
      var action=identityState.action,keepProfile=identityState.source,addProfile=action==='merge'?document.getElementById('identityTarget').value:identityState.target;
      var url=action==='merge'?'/api/merge-visitors':'/api/unmerge-visitor';
      var payload=action==='merge'?{source:addProfile,target:keepProfile}:{visitorId:keepProfile,canonicalId:addProfile};
      if(action==='merge'&&!document.getElementById('identityApproval').checked)return;
      confirm.disabled=true;confirm.textContent='Saving…';err.hidden=true;
      fetch(url,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})
        .then(function(r){return r.json().then(function(d){return{status:r.status,data:d};});})
        .then(function(result){if(result.data&&result.data.ok){location.reload();return;}err.textContent=(result.data&&result.data.message)||('Could not save ('+((result.data&&result.data.error)||result.status)+'). Refresh and try again.');err.hidden=false;confirm.textContent=action==='merge'?'Combine into this profile':'Unlink ID';identityReview();})
        .catch(function(){err.textContent='Network error. Please try again.';err.hidden=false;confirm.textContent=action==='merge'?'Combine into this profile':'Unlink ID';identityReview();});
    });
  }
  document.addEventListener('click',function(e){
    var merge=e.target.closest('.profile-merge');
    if(merge){e.preventDefault();identityOpen('merge',merge.getAttribute('data-vid'));return;}
    var separate=e.target.closest('.profile-separate');
    if(separate){e.preventDefault();identityOpen('separate',separate.getAttribute('data-member'),separate.getAttribute('data-canonical'));}
  });

  var visitDialog=document.getElementById('visitDialog'),visitProfile='',visitRows=[],selectedVisit=null;
  function visitError(message){var el=document.getElementById('visitError');el.textContent=message;el.hidden=false;}
  function visitRowLabel(v){return (v.city||v.region||v.country||'Unknown area')+' · '+(v.os||v.device_type||'Unknown device')+' · '+(v.browser||'Unknown browser');}
  function renderVisitList(){
    var list=document.getElementById('visitList');
    list.innerHTML=visitRows.length?visitRows.map(function(v){return '<div class="visit-item"><div><strong>'+escH(visitRowLabel(v))+'</strong><small>'+escH(fmtH(v.created_at))+' · '+escH(v.isp||'Unknown network')+(v.network_signal?' · network '+escH(v.network_signal):'')+'</small><small>Visit #'+v.id+(v.override_id?' · moved from original ID '+escH(v.original_id.slice(0,10)):'')+'</small></div><button type="button" class="'+(v.override_id?'visit-restore':'visit-select')+'" data-view-id="'+v.id+'">'+(v.override_id?'Undo move':'Move visit')+'</button></div>';}).join(''):'<p class="identity-note">No visits found in this profile.</p>';
  }
  function openVisitDialog(profile){
    if(!visitDialog)return;
    visitProfile=profile;visitRows=[];selectedVisit=null;
    document.getElementById('visitDialogTitle').textContent='Review visits · '+profile.slice(0,10);
    document.getElementById('visitList').innerHTML='<p class="identity-note">Loading visits…</p>';
    document.getElementById('visitEditor').hidden=true;
    document.getElementById('visitError').hidden=true;
    visitDialog.showModal();
    fetch('/api/profile-visits?profile='+encodeURIComponent(profile),{credentials:'same-origin'})
      .then(function(r){if(!r.ok)throw Error('Could not load visits ('+r.status+').');return r.json();})
      .then(function(d){visitRows=d.visits||[];renderVisitList();if(d.hasMore)visitError('Showing the latest 100 visits only.');})
      .catch(function(err){visitError(err.message||'Could not load visits.');document.getElementById('visitList').innerHTML='';});
  }
  if(visitDialog){
    document.getElementById('visitClose').addEventListener('click',function(){visitDialog.close();});
    document.getElementById('visitCancelMove').addEventListener('click',function(){document.getElementById('visitEditor').hidden=true;selectedVisit=null;});
    document.getElementById('visitList').addEventListener('click',function(e){
      var button=e.target.closest('button[data-view-id]');if(!button)return;
      var id=Number(button.getAttribute('data-view-id'));
      var visit=visitRows.find(function(v){return v.id===id;});if(!visit)return;
      var err=document.getElementById('visitError');err.hidden=true;
      if(button.classList.contains('visit-restore')){
        button.disabled=true;button.textContent='Restoring…';
        fetch('/api/restore-visit',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({viewId:id,profileId:visitProfile})})
          .then(function(r){return r.json();}).then(function(d){if(d.ok){location.reload();return;}visitError(d.message||'Could not undo the move. Refresh and try again.');button.disabled=false;button.textContent='Undo move';})
          .catch(function(){visitError('Network error. Please try again.');button.disabled=false;button.textContent='Undo move';});
        return;
      }
      selectedVisit=visit;
      document.getElementById('visitSelected').textContent='Move visit #'+id+' · '+visitRowLabel(visit)+' · '+fmtH(visit.created_at);
      var select=document.getElementById('visitDestination');select.innerHTML='';
      var fresh=document.createElement('option');fresh.value='new';fresh.textContent='Create a new separate profile';select.appendChild(fresh);
      ((_sd&&_sd.profiles)||[]).filter(function(p){return p.id!==visitProfile;}).forEach(function(p){var o=document.createElement('option');o.value=p.id;o.textContent='Existing: '+p.id.slice(0,10)+' · '+identitySummary(p);select.appendChild(o);});
      document.getElementById('visitEditor').hidden=false;
    });
    document.getElementById('visitConfirmMove').addEventListener('click',function(){
      if(!selectedVisit)return;
      var button=this;button.disabled=true;button.textContent='Moving…';
      fetch('/api/move-visit',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({viewId:selectedVisit.id,fromProfile:visitProfile,targetProfile:document.getElementById('visitDestination').value})})
        .then(function(r){return r.json();}).then(function(d){if(d.ok){location.reload();return;}visitError(d.message||'Could not move this visit. Refresh and try again.');button.disabled=false;button.textContent='Move visit';})
        .catch(function(){visitError('Network error. Please try again.');button.disabled=false;button.textContent='Move visit';});
    });
  }
  document.addEventListener('click',function(e){var button=e.target.closest('.profile-review');if(button){e.preventDefault();openVisitDialog(button.getAttribute('data-vid'));}});

  // ── Delete data: per-visit, per-interaction, per-profile, bulk + danger zone ──
  function apiDelete(scope,ids){
    return fetch('/api/delete',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({scope:scope,ids:ids||[]})})
      .then(function(r){return r.json().catch(function(){return{ok:false,error:'bad_response'};});});
  }
  function selectedIds(tbodyId){
    var out=[],body=document.getElementById(tbodyId);
    if(!body)return out;
    Array.prototype.forEach.call(body.querySelectorAll('.row-chk:checked'),function(c){var id=c.getAttribute('data-id');if(id)out.push(id);});
    return out;
  }
  function updateBulkBar(which){
    var isRecent=which==='recent';
    var tbody=document.getElementById(isRecent?'recentTbody':'clickTbody');
    if(!tbody)return;
    var bar=document.getElementById(isRecent?'recentBulk':'clickBulk');
    var cnt=document.getElementById(isRecent?'recentSelCount':'clickSelCount');
    var all=document.getElementById(isRecent?'recentAll':'clickAll');
    var n=selectedIds(isRecent?'recentTbody':'clickTbody').length;
    if(cnt)cnt.textContent=n;
    if(bar)bar.hidden=(n===0);
    if (all) {
      var count = tbody.querySelectorAll('.row-chk').length;
      all.checked = n > 0 && n === count;
      all.indeterminate = n > 0 && n < count;
      all.disabled = count === 0;
    }
  }
  document.addEventListener('change',function(e){
    var t=e.target;if(!t)return;
    if(t.classList&&t.classList.contains('row-chk')){updateBulkBar(t.closest('#clickTbody')?'click':'recent');}
    else if(t.id==='recentAll'||t.id==='clickAll'){
      var which=t.id==='recentAll'?'recent':'click';
      Array.prototype.forEach.call(document.getElementById(which==='recent'?'recentTbody':'clickTbody').querySelectorAll('.row-chk'),function(c){c.checked=t.checked;});
      updateBulkBar(which);
    }
  });
  function runDelete(scope,ids,opts){
    opts=opts||{};
    var btn=opts.btn;
    if(btn){btn.disabled=true;btn.dataset.t=btn.textContent;btn.textContent=opts.busy||'Deleting…';}
    return apiDelete(scope,ids).then(function(d){
      if(d&&d.ok){location.reload();return;}
      alert('Delete failed: '+((d&&d.error)||'unknown'));
      if(btn){btn.disabled=false;btn.textContent=btn.dataset.t||'Delete';}
    }).catch(function(){alert('Network error');if(btn){btn.disabled=false;btn.textContent=btn.dataset.t||'Delete';}});
  }
  document.addEventListener('click',function(e){
    var del=e.target.closest('.row-del');
    if(del){
      e.preventDefault();e.stopPropagation();
      var kind=del.getAttribute('data-kind'),id=del.getAttribute('data-id');
      if(!kind||!id)return;
      if(!confirm('Delete '+(kind==='visit'?'this visit and its activity':'this interaction')+'? This cannot be undone.'))return;
      runDelete(kind,[id],{btn:del,busy:'…'});
      return;
    }
    var pd=e.target.closest('.profile-delete');
    if(pd){
      e.preventDefault();e.stopPropagation();
      var vid=pd.getAttribute('data-vid');if(!vid)return;
      if(!confirm('Delete profile '+vid.slice(0,10)+' and ALL of its visits, interactions and identity links? This cannot be undone.'))return;
      runDelete('visitor',[vid],{btn:pd,busy:'Deleting…'});
      return;
    }
    if(e.target.closest('#recentBulkDelete')){
      var rids=selectedIds('recentTbody');if(!rids.length)return;
      if(!confirm('Delete '+rids.length+' selected visit'+(rids.length>1?'s':'')+' and their activity? This cannot be undone.'))return;
      runDelete('visit',rids,{btn:document.getElementById('recentBulkDelete')});
      return;
    }
    if(e.target.closest('#clickBulkDelete')){
      var cids=selectedIds('clickTbody');if(!cids.length)return;
      if(!confirm('Delete '+cids.length+' selected interaction'+(cids.length>1?'s':'')+'? This cannot be undone.'))return;
      runDelete('engagement',cids,{btn:document.getElementById('clickBulkDelete')});
      return;
    }
    if(e.target.closest('#recentClearSel')){Array.prototype.forEach.call(document.getElementById('recentTbody').querySelectorAll('.row-chk'),function(c){c.checked=false;});updateBulkBar('recent');return;}
    if(e.target.closest('#clickClearSel')){Array.prototype.forEach.call(document.getElementById('clickTbody').querySelectorAll('.row-chk'),function(c){c.checked=false;});updateBulkBar('click');return;}
    var dz=e.target.closest('.danger-btn[data-danger]');
    if(dz){
      var scope=dz.getAttribute('data-danger');
      var msg=scope==='all'?'Delete ALL analytics data (every visit, interaction, engagement row and identity link)? This cannot be undone.'
        :scope==='all_visits'?'Delete ALL visits and identity corrections? Clicks/engagement are kept. This cannot be undone.'
        :'Delete ALL clicks & engagement? Visits are kept. This cannot be undone.';
      if(!confirm(msg))return;
      if(scope==='all'&&!confirm('Final confirmation — permanently erase all analytics data?'))return;
      runDelete(scope,[],{btn:dz,busy:'Deleting…'});
      return;
    }
  });

  var FAVORITES_KEY = 'dash-favorites';
  var favorites = [];
  var dismissedFavorite = '';
  try {
    var stored = JSON.parse(localStorage.getItem(FAVORITES_KEY));
    if (Array.isArray(stored)) favorites = stored.filter(function(id) { return typeof id === 'string'; });
  } catch (e) {}
  function getFavorites() { return favorites; }
  function applyFavorites() {
    document.querySelectorAll('tr[data-vid]').forEach(function(row) {
      row.classList.toggle('favorite-visit', favorites.includes(row.dataset.vid));
    });
  }
  function showFavoriteAlert() {
    var latest = _sd.profiles.filter(function(profile) {
      return favorites.includes(profile.id) && profile.lastSeen;
    }).sort(function(a, b) { return b.lastSeen.localeCompare(a.lastSeen); })[0];
    var alert = el('favoriteAlert');
    var age = latest ? Date.now() - new Date(latest.lastSeen + 'Z').getTime() : Infinity;
    var key = latest ? latest.id + latest.lastSeen : '';
    alert.hidden = age < 0 || age >= 86400000 || dismissedFavorite === key;
    if (alert.hidden || alert.dataset.visit === key) return;
    alert.dataset.visit = key;
    alert.innerHTML = '<span aria-hidden="true">★</span><span><strong>' + escH(profileName(latest))
      + '</strong> visited ' + fmtH(latest.lastSeen) + '</span><button type="button" aria-label="Dismiss saved visit alert">Dismiss</button>';
  }
  el('favoriteAlert').addEventListener('click', function(e) {
    if (!e.target.closest('button')) return;
    dismissedFavorite = this.dataset.visit;
    this.hidden = true;
    el('overviewTitle').focus({preventScroll:true});
  });
  document.addEventListener('click', function(e) {
    var button = e.target.closest('.favorite-btn');
    if (!button) return;
    var id = button.dataset.vid;
    favorites = favorites.includes(id) ? favorites.filter(function(value) { return value !== id; }) : favorites.concat(id);
    try { localStorage.setItem(FAVORITES_KEY, JSON.stringify(favorites)); } catch (error) {}
    renderProfiles();
    applyFavorites();
    showFavoriteAlert();
  });

  selectView(false);
  renderDashboardData();
`;
