// SPDX-License-Identifier: Apache-2.0
//
// Everything here adds to a page that already reads well without it.

const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

const byId = (id) => document.getElementById(id);
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/* A lattice, the structure ML-KEM and ML-DSA are built on. It drifts, and bends near the pointer. */
function startLattice() {
  const canvas = byId("lattice");
  const context = canvas.getContext("2d");
  const spacing = 58;
  const pointerReach = 170;
  const pointer = { x: -1000, y: -1000 };
  let width = 0;
  let height = 0;
  let running = false;

  function resize() {
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    width = canvas.clientWidth;
    height = canvas.clientHeight;
    canvas.width = width * ratio;
    canvas.height = height * ratio;
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
  }

  function nodeAt(column, row, time) {
    const baseX = column * spacing + (row % 2) * (spacing / 2);
    const baseY = row * spacing * 0.86;
    const phase = column * 0.7 + row * 1.3;
    let x = baseX + Math.sin(time * 0.5 + phase) * 7;
    let y = baseY + Math.cos(time * 0.4 + phase) * 7;
    const dx = x - pointer.x;
    const dy = y - pointer.y;
    const distance = Math.hypot(dx, dy) || 1;
    const push = Math.max(0, 1 - distance / pointerReach);
    x += (dx / distance) * push * 26;
    y += (dy / distance) * push * 26;
    return { x, y, glow: push };
  }

  function drawEdge(from, to) {
    context.strokeStyle = `rgba(203, 166, 247, ${0.1 + Math.max(from.glow, to.glow) * 0.4})`;
    context.beginPath();
    context.moveTo(from.x, from.y);
    context.lineTo(to.x, to.y);
    context.stroke();
  }

  function draw(time) {
    context.clearRect(0, 0, width, height);
    const columns = Math.ceil(width / spacing) + 2;
    const rows = Math.ceil(height / (spacing * 0.86)) + 2;
    for (let row = 0; row < rows; row++) {
      for (let column = 0; column < columns; column++) {
        const node = nodeAt(column, row, time);
        const step = row % 2;
        if (column + 1 < columns) drawEdge(node, nodeAt(column + 1, row, time));
        if (row + 1 < rows) drawEdge(node, nodeAt(column + step, row + 1, time));
        context.fillStyle = `rgba(180, 190, 254, ${0.2 + node.glow * 0.7})`;
        context.beginPath();
        context.arc(node.x, node.y, 1.6 + node.glow * 2, 0, Math.PI * 2);
        context.fill();
      }
    }
  }

  function frame(now) {
    if (!running) return;
    draw(now / 1000);
    requestAnimationFrame(frame);
  }

  function setRunning(next) {
    if (next === running) return;
    running = next;
    if (running) requestAnimationFrame(frame);
  }

  resize();
  window.addEventListener("resize", () => {
    resize();
    if (reducedMotion) draw(0);
  });

  if (reducedMotion) {
    draw(0);
    return;
  }

  byId("top").addEventListener("pointermove", (event) => {
    const box = canvas.getBoundingClientRect();
    pointer.x = event.clientX - box.left;
    pointer.y = event.clientY - box.top;
  });
  byId("top").addEventListener("pointerleave", () => {
    pointer.x = -1000;
    pointer.y = -1000;
  });

  // Nothing is drawn while the hero is off screen or the tab is hidden.
  let onScreen = true;
  new IntersectionObserver(([entry]) => {
    onScreen = entry.isIntersecting;
    setRunning(onScreen && !document.hidden);
  }).observe(canvas);
  document.addEventListener("visibilitychange", () => setRunning(onScreen && !document.hidden));
  setRunning(true);
}

/* Replays the real output that is already in the page, line by line. */
function startTerminal() {
  const lines = [...document.querySelectorAll("#hero-terminal .term-line")];
  const replay = byId("replay");
  let run = 0;

  async function typeCommand(line, current) {
    const typed = line.querySelector(".typed");
    const command = line.dataset.command;
    typed.textContent = "";
    typed.classList.add("is-typing");
    line.style.visibility = "visible";
    await wait(380);
    for (const letter of command) {
      if (run !== current) return;
      typed.textContent += letter;
      await wait(55 + Math.random() * 45);
    }
    await wait(260);
    typed.classList.remove("is-typing");
  }

  async function play() {
    run += 1;
    const current = run;
    replay.hidden = true;
    lines.forEach((line) => {
      line.style.visibility = "hidden";
      line.querySelector(".typed")?.classList.remove("is-typing");
    });
    for (const line of lines) {
      if (run !== current) return;
      if (line.dataset.command) {
        await typeCommand(line, current);
      } else {
        line.style.visibility = "visible";
        await wait(70);
      }
    }
    if (run === current) replay.hidden = false;
  }

  if (reducedMotion) return;
  replay.addEventListener("click", play);
  play();
}

function startReveals() {
  const items = document.querySelectorAll(".reveal");
  if (reducedMotion || !("IntersectionObserver" in window)) {
    items.forEach((item) => item.classList.add("is-visible"));
    return;
  }
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.12, rootMargin: "0px 0px -6% 0px" },
  );
  items.forEach((item) => observer.observe(item));
}

function startScrollEffects() {
  const bar = byId("progress-bar");
  const topbar = byId("topbar");
  let scheduled = false;

  function update() {
    scheduled = false;
    const range = document.documentElement.scrollHeight - window.innerHeight;
    bar.style.transform = `scaleX(${range > 0 ? window.scrollY / range : 0})`;
    topbar.classList.toggle("is-scrolled", window.scrollY > 40);
  }

  window.addEventListener(
    "scroll",
    () => {
      if (!scheduled) {
        scheduled = true;
        requestAnimationFrame(update);
      }
    },
    { passive: true },
  );
  update();
}

function startScrollSpy() {
  const links = new Map(
    [...document.querySelectorAll(".topnav a")].map((link) => [link.hash.slice(1), link]),
  );
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        const link = links.get(entry.target.id);
        link.classList.toggle("is-current", entry.isIntersecting);
        if (entry.isIntersecting) {
          link.parentElement.parentElement.scrollTo({ left: link.offsetLeft - 40 });
        }
      });
    },
    { rootMargin: "-45% 0px -50% 0px" },
  );
  links.forEach((_, id) => observer.observe(byId(id)));
}

function startCounters() {
  if (reducedMotion) return;
  document.querySelectorAll("[data-count]").forEach((counter) => {
    const target = Number(counter.dataset.count);
    const start = performance.now();
    const duration = 1400;
    function tick(now) {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - (1 - progress) ** 3;
      counter.textContent = String(Math.round(target * eased));
      if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  });
}

function startTimeline() {
  const today = byId("today");
  const first = Date.UTC(2024, 0, 1);
  const last = Date.UTC(2036, 0, 1);
  const position = (Date.now() - first) / (last - first);
  today.style.left = `${Math.min(Math.max(position, 0), 1) * 100}%`;
  today.hidden = false;
}

/* The same score as src/risk/priority.c, for a migration that starts this year. */
function priorityOf(x, y, q) {
  const end = new Date().getUTCFullYear() + y;
  const deadline = end > 2035 ? 20 : end > 2030 ? 10 : 0;
  return 50 + deadline + Math.min(Math.max(10 + x + y - q, 0), 29);
}

function startMosca() {
  const inputs = { x: byId("x"), y: byId("y"), q: byId("q") };
  const result = byId("mosca-result");
  const score = byId("mosca-score");
  const scale = 45;

  function update() {
    const x = Number(inputs.x.value);
    const y = Number(inputs.y.value);
    const q = Number(inputs.q.value);
    byId("x-value").textContent = x;
    byId("y-value").textContent = y;
    byId("q-value").textContent = q;
    byId("bar-x").style.width = `${(x / scale) * 100}%`;
    byId("bar-y").style.width = `${(y / scale) * 100}%`;
    byId("bar-q").style.width = `${(q / scale) * 100}%`;
    const exposed = x + y - q;
    const years = exposed === 1 ? "year" : "years";
    result.textContent =
      exposed > 0
        ? `X + Y = ${x + y} > ${q}: data stays exposed for ${exposed} ${years}.`
        : `X + Y = ${x + y} ≤ ${q}: you finish in time, by these numbers.`;
    result.className = `mosca-result ${exposed > 0 ? "is-exposed" : "is-safe"}`;
    score.textContent = `pqscan would give a quantum-vulnerable finding here priority ${priorityOf(x, y, q)}.`;
  }

  Object.values(inputs).forEach((input) => input.addEventListener("input", update));
  update();
}

/* The constant flow example: each call lights up with what pqscan resolved for it. */
function startFlow() {
  const flow = byId("flow");
  const lines = [...flow.querySelectorAll(".flow-line[data-result]")];
  const results = [...flow.querySelectorAll("li[data-result]")];
  if (reducedMotion) {
    results.forEach((item) => item.classList.add("is-seen"));
    return;
  }

  let step = 0;
  let timer = null;

  function show() {
    lines.forEach((line, index) => line.classList.toggle("is-current", index === step));
    results.forEach((item, index) => {
      item.classList.toggle("is-current", index === step);
      item.classList.toggle("is-seen", index <= step);
    });
    step = (step + 1) % lines.length;
  }

  new IntersectionObserver(
    ([entry]) => {
      clearInterval(timer);
      if (entry.isIntersecting) {
        show();
        timer = setInterval(show, 1500);
      }
    },
    { threshold: 0.3 },
  ).observe(flow);
}

function startTabs() {
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  const indicator = byId("tab-indicator");

  function moveIndicator(tab) {
    indicator.style.width = `${tab.offsetWidth}px`;
    indicator.style.transform = `translateX(${tab.offsetLeft}px)`;
  }

  function select(tab, focus) {
    tabs.forEach((other) => {
      const selected = other === tab;
      other.setAttribute("aria-selected", String(selected));
      other.tabIndex = selected ? 0 : -1;
      byId(other.getAttribute("aria-controls")).hidden = !selected;
    });
    moveIndicator(tab);
    if (focus) tab.focus();
  }

  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => select(tab, false));
    tab.addEventListener("keydown", (event) => {
      const moves = { ArrowRight: 1, ArrowLeft: -1 };
      if (event.key in moves) {
        event.preventDefault();
        select(tabs[(index + moves[event.key] + tabs.length) % tabs.length], true);
      }
    });
  });

  window.addEventListener("resize", () => moveIndicator(tabs.find((tab) => tab.tabIndex === 0)));
  document.fonts?.ready.then(() => moveIndicator(tabs.find((tab) => tab.tabIndex === 0)));
  moveIndicator(tabs[0]);
}

/* The same decision as exit_code_of() in src/cli/run.c. */
function startExitCodes() {
  const skipped = byId("gate-skipped");
  const exit = byId("gate-exit");
  const code = byId("gate-code");
  const meaning = byId("gate-meaning");
  const counts = [1, 2, 3].map((level) => byId(`count-${level}`));

  function failing(threshold) {
    return counts.reduce((sum, input, index) => {
      const level = index + 1;
      return level >= threshold ? sum + (Number(input.value) || 0) : sum;
    }, 0);
  }

  function describe(found, incomplete) {
    if (found > 0) {
      const plural = found === 1 ? "finding is" : "findings are";
      const suffix = incomplete ? " The scan was also incomplete, but findings win." : "";
      return { value: 1, text: `${found} ${plural} at or above the threshold.${suffix}` };
    }
    if (incomplete) {
      return { value: 4, text: "Nothing at or above the threshold, but the scan is incomplete." };
    }
    return { value: 0, text: "Nothing at or above the threshold, and everything was analyzed." };
  }

  function update() {
    const threshold = Number(document.querySelector('[name="fail-on"]:checked').value);
    const verdict = describe(failing(threshold), skipped.checked);
    if (code.textContent !== String(verdict.value)) {
      exit.classList.remove("is-changing");
      void exit.offsetWidth; // Restarts the animation.
      exit.classList.add("is-changing");
    }
    code.textContent = verdict.value;
    exit.dataset.exit = verdict.value;
    meaning.textContent = verdict.text;
  }

  byId("gate").addEventListener("input", update);
  update();
}

function escapeHtml(text) {
  return text.replace(/[&<>]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[char]);
}

function highlightJson() {
  const token = /("(?:[^"\\]|\\.)*")(\s*:)?|\b(true|false|null)\b|\b(\d+)\b/g;
  document.querySelectorAll("pre[data-json] code").forEach((code) => {
    code.innerHTML = escapeHtml(code.textContent).replace(
      token,
      (match, string, colon, literal, number) => {
        if (string) {
          const kind = colon ? "t-key" : "t-string";
          return `<span class="${kind}">${string}</span>${colon ?? ""}`;
        }
        return `<span class="${literal ? "t-literal" : "t-number"}">${match}</span>`;
      },
    );
  });
}

function startCopyButtons() {
  document.querySelectorAll(".copy").forEach((button) => {
    button.addEventListener("click", async () => {
      const text = button.closest(".code-block").querySelector("pre").textContent;
      try {
        await navigator.clipboard.writeText(text);
        button.textContent = "Copied";
        button.classList.add("is-done");
      } catch {
        button.textContent = "Press Ctrl+C";
      }
      setTimeout(() => {
        button.textContent = "Copy";
        button.classList.remove("is-done");
      }, 1600);
    });
  });
}

function startCardGlow() {
  document.querySelectorAll(".card").forEach((card) => {
    card.addEventListener("pointermove", (event) => {
      const box = card.getBoundingClientRect();
      card.style.setProperty("--mx", `${event.clientX - box.left}px`);
      card.style.setProperty("--my", `${event.clientY - box.top}px`);
    });
  });
}

highlightJson();
startLattice();
startTerminal();
startReveals();
startScrollEffects();
startScrollSpy();
startCounters();
startTimeline();
startMosca();
startFlow();
startTabs();
startExitCodes();
startCopyButtons();
startCardGlow();
