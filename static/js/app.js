// กราฟบนแดชบอร์ด (Chart.js) อ่านข้อมูลจาก <script id="chart-data" type="application/json">
(function () {
  var el = document.getElementById('chart-data');
  if (!el || !window.Chart) return;
  var data = JSON.parse(el.textContent);
  var SEV = { critical: '#B91C1C', high: '#EA580C', medium: '#CA8A04', low: '#2563EB' };
  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  Chart.defaults.font.family = '"IBM Plex Sans Thai", "Noto Sans Thai", system-ui, sans-serif';
  Chart.defaults.font.size = 13;
  Chart.defaults.color = '#475569';
  if (reduce) Chart.defaults.animation = false;

  var donut = document.getElementById('chart-severity');
  if (donut) {
    new Chart(donut, {
      type: 'doughnut',
      data: {
        labels: data.severity.labels,
        datasets: [{ data: data.severity.data, backgroundColor: Object.values(SEV), borderColor: '#FFFFFF', borderWidth: 2 }]
      },
      options: { cutout: '65%', maintainAspectRatio: false, plugins: { legend: { display: false } } }
    });
  }

  var bar = document.getElementById('chart-locations');
  if (bar) {
    new Chart(bar, {
      type: 'bar',
      data: {
        labels: data.locations.labels,
        datasets: data.locations.series.map(function (s) {
          return { label: s.label, data: s.data, backgroundColor: SEV[s.key], borderRadius: 3, maxBarThickness: 26 };
        })
      },
      options: {
        indexAxis: 'y', maintainAspectRatio: false,
        scales: { x: { stacked: true, beginAtZero: true, ticks: { precision: 0 }, grid: { color: '#E2E8F0' } }, y: { stacked: true, grid: { display: false } } },
        plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, boxHeight: 12 } } }
      }
    });
  }

  var line = document.getElementById('chart-trend');
  if (line) {
    new Chart(line, {
      type: 'line',
      data: {
        labels: data.trend.labels,
        datasets: [
          { label: 'พบใหม่', data: data.trend.found, borderColor: '#B91C1C', backgroundColor: '#B91C1C', tension: .3, pointRadius: 4 },
          { label: 'แก้ไขแล้ว', data: data.trend.fixed, borderColor: '#15803D', backgroundColor: '#15803D', borderDash: [6, 4], tension: .3, pointRadius: 4, pointStyle: 'rect' }
        ]
      },
      options: {
        maintainAspectRatio: false,
        scales: { y: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: '#E2E8F0' } }, x: { grid: { display: false } } },
        plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, boxHeight: 12 } } }
      }
    });
  }
})();

// เมนูบนมือถือ: ปุ่มเปิด/ปิด, กดพื้นหลังหรือกด Esc เพื่อปิด
(function () {
  var button = document.getElementById('menu-button');
  if (!button) return;
  function setOpen(open) {
    document.body.classList.toggle('menu-open', open);
    button.setAttribute('aria-expanded', String(open));
    button.setAttribute('aria-label', open ? 'ปิดเมนู' : 'เปิดเมนู');
    if (open) {
      var first = document.querySelector('.sidebar a');
      if (first) first.focus();
    }
  }
  button.addEventListener('click', function () { setOpen(!document.body.classList.contains('menu-open')); });
  document.addEventListener('click', function (e) {
    if (e.target.closest('[data-close-menu]') || e.target.closest('.sidebar a')) setOpen(false);
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && document.body.classList.contains('menu-open')) { setOpen(false); button.focus(); }
  });
})();

// ปุ่มพิมพ์รายงาน
document.addEventListener('click', function (e) {
  if (e.target.closest('[data-print]')) window.print();
});
