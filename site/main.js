// SPDX-License-Identifier: Apache-2.0
//
// Everything here adds to a page that already reads well without it.

const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const lightScheme = window.matchMedia("(prefers-color-scheme: light)");

const byId = (id) => document.getElementById(id);
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const clamp = (value, low, high) => Math.min(Math.max(value, low), high);

/* Runs every scroll handler once per frame, however often the page scrolls. */
const scrollHandlers = [];
function onScroll(handler) {
  scrollHandlers.push(handler);
  handler();
}
let scrollScheduled = false;
function runScrollHandlers() {
  scrollScheduled = false;
  scrollHandlers.forEach((handler) => handler());
}
window.addEventListener(
  "scroll",
  () => {
    if (!scrollScheduled) {
      scrollScheduled = true;
      requestAnimationFrame(runScrollHandlers);
    }
  },
  { passive: true },
);
window.addEventListener("resize", runScrollHandlers);

/* A lattice, the structure ML-KEM and ML-DSA are built on. It drifts, and bends near the pointer. */
function startLattice() {
  const canvas = byId("lattice");
  const context = canvas.getContext("2d");
  const spacing = 64;
  const pointerReach = 180;
  const pointer = { x: -1000, y: -1000 };
  let color = "255, 255, 255";
  let width = 0;
  let height = 0;
  let running = false;

  function readColor() {
    color = getComputedStyle(document.documentElement).getPropertyValue("--lattice").trim();
  }

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
    let x = baseX + Math.sin(time * 0.4 + phase) * 6;
    let y = baseY + Math.cos(time * 0.3 + phase) * 6;
    const dx = x - pointer.x;
    const dy = y - pointer.y;
    const distance = Math.hypot(dx, dy) || 1;
    const push = Math.max(0, 1 - distance / pointerReach);
    x += (dx / distance) * push * 24;
    y += (dy / distance) * push * 24;
    return { x, y, glow: push };
  }

  function drawEdge(from, to) {
    context.strokeStyle = `rgba(${color}, ${0.07 + Math.max(from.glow, to.glow) * 0.3})`;
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
        context.fillStyle = `rgba(${color}, ${0.16 + node.glow * 0.6})`;
        context.beginPath();
        context.arc(node.x, node.y, 1.4 + node.glow * 1.8, 0, Math.PI * 2);
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

  readColor();
  resize();
  window.addEventListener("resize", () => {
    resize();
    if (reducedMotion) draw(0);
  });
  lightScheme.addEventListener("change", () => {
    readColor();
    if (reducedMotion) draw(0);
  });

  if (reducedMotion) {
    draw(0);
    return;
  }

  const hero = byId("top");
  hero.addEventListener("pointermove", (event) => {
    const box = canvas.getBoundingClientRect();
    pointer.x = event.clientX - box.left;
    pointer.y = event.clientY - box.top;
  });
  hero.addEventListener("pointerleave", () => {
    pointer.x = -1000;
    pointer.y = -1000;
  });

  // Nothing is drawn while the hero is off screen or the tab is hidden.
  let onScreen = true;
  new IntersectionObserver(([entry]) => {
    onScreen = entry.isIntersecting;
    setRunning(onScreen && !document.hidden);
  }).observe(hero);
  document.addEventListener("visibilitychange", () => setRunning(onScreen && !document.hidden));
  setRunning(true);
}

/* Depth. "fixed" layers float on a slow wave as the page scrolls, "lag" layers fall behind the
   page, and the rest drift from the middle of the screen in proportion to their speed. */
function startParallax() {
  if (reducedMotion) return;
  const layers = [...document.querySelectorAll("[data-parallax]")].map((element, index) => ({
    element,
    index,
    speed: Number(element.dataset.parallax),
    mode: element.closest(".backdrop") ? "fixed" : element.dataset.parallaxMode || "float",
  }));

  function offsetOf(layer) {
    const scroll = window.scrollY;
    if (layer.mode === "fixed") return Math.sin((scroll * layer.speed) / 260 + layer.index * 2) * 140;
    if (layer.mode === "lag") return Math.min(scroll, window.innerHeight * 1.2) * layer.speed;
    const box = layer.element.getBoundingClientRect();
    if (box.bottom < -200 || box.top > window.innerHeight + 200) return null;
    return (box.top + box.height / 2 - window.innerHeight / 2) * layer.speed;
  }

  onScroll(() => {
    layers.forEach((layer) => {
      const offset = offsetOf(layer);
      if (offset !== null) layer.element.style.translate = `0 ${offset.toFixed(1)}px`;
    });
  });
}

/* How far the hero has scrolled, from 0 to 1, which tilts the terminal flat and lifts the title. */
function startHeroProgress() {
  const root = document.documentElement;
  if (reducedMotion) return;
  onScroll(() => {
    const progress = clamp(window.scrollY / (window.innerHeight * 0.55), 0, 1);
    root.style.setProperty("--hero-progress", progress.toFixed(3));
  });
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
    await wait(420);
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

/* Tiles that share a grid come in one after another. */
function startReveals() {
  const items = document.querySelectorAll(".reveal");
  if (reducedMotion || !("IntersectionObserver" in window)) {
    items.forEach((item) => item.classList.add("is-visible"));
    return;
  }
  document.querySelectorAll(".bento, .kinds, .levels, .releases").forEach((grid) => {
    [...grid.children].forEach((child, index) => {
      child.style.setProperty("--delay", `${(index % 4) * 80}ms`);
    });
  });
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.1, rootMargin: "0px 0px -6% 0px" },
  );
  items.forEach((item) => observer.observe(item));
}

/* Moves a lens to sit under an element of the same scroll container. */
function placeLens(lens, target) {
  lens.style.width = `${target.offsetWidth}px`;
  lens.style.transform = `translateX(${target.offsetLeft}px)`;
}

/* The nav grows a shadow once the page moves, and its lens follows the section in view. */
function startNav() {
  const nav = byId("nav");
  const list = byId("nav-links");
  const lens = byId("nav-lens");
  const links = new Map(
    [...list.querySelectorAll("a")].map((link) => [link.hash.slice(1), link]),
  );
  let current = null;

  onScroll(() => nav.classList.toggle("is-scrolled", window.scrollY > 24));

  function show(link) {
    links.forEach((other) => other.classList.toggle("is-current", other === link));
    current = link;
    if (!link) {
      lens.classList.remove("is-on");
      return;
    }
    placeLens(lens, link);
    lens.classList.add("is-on");
    list.scrollTo({ left: link.offsetLeft - 48, behavior: reducedMotion ? "auto" : "smooth" });
  }

  const visible = new Set();
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) visible.add(entry.target.id);
        else visible.delete(entry.target.id);
      });
      const id = [...links.keys()].find((key) => visible.has(key));
      show(id ? links.get(id) : null);
    },
    { rootMargin: "-45% 0px -50% 0px" },
  );
  links.forEach((_, id) => observer.observe(byId(id)));
  window.addEventListener("resize", () => current && placeLens(lens, current));
}

function startCounters() {
  if (reducedMotion) return;
  const counters = document.querySelectorAll("[data-count]");
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;
      observer.unobserve(entry.target);
      const counter = entry.target;
      const target = Number(counter.dataset.count);
      const start = performance.now();
      const duration = 1600;
      function tick(now) {
        const progress = Math.min((now - start) / duration, 1);
        const eased = 1 - (1 - progress) ** 4;
        counter.textContent = String(Math.round(target * eased));
        if (progress < 1) requestAnimationFrame(tick);
      }
      requestAnimationFrame(tick);
    });
  });
  counters.forEach((counter) => observer.observe(counter));
}

function startTimeline() {
  const today = byId("today");
  const first = Date.UTC(2024, 0, 1);
  const last = Date.UTC(2036, 0, 1);
  const position = (Date.now() - first) / (last - first);
  today.style.left = `${clamp(position, 0, 1) * 100}%`;
  today.hidden = false;
}

/* The same score as src/risk/priority.c, for a migration that starts this year. */
function priorityOf(x, y, q) {
  const end = new Date().getUTCFullYear() + y;
  const deadline = end > 2035 ? 20 : end > 2030 ? 10 : 0;
  return 50 + deadline + clamp(10 + x + y - q, 0, 29);
}

/* Fills a range track up to its thumb, which WebKit cannot do by itself. */
function fillRange(input) {
  const share = (input.value - input.min) / (input.max - input.min);
  input.style.setProperty("--fill", `${share * 100}%`);
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
    Object.values(inputs).forEach(fillRange);
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

/* Segmented controls. Panels are only hidden here, so that all of them show without JavaScript. */
function startTabs() {
  document.querySelectorAll("[data-tabs]").forEach((group) => {
    const tabs = [...group.querySelectorAll('[role="tab"]')];
    const lens = group.querySelector(".segmented-lens");

    function select(tab, focus) {
      tabs.forEach((other) => {
        const selected = other === tab;
        other.setAttribute("aria-selected", String(selected));
        other.tabIndex = selected ? 0 : -1;
        byId(other.getAttribute("aria-controls")).hidden = !selected;
      });
      placeLens(lens, tab);
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

    const selected = () => tabs.find((tab) => tab.tabIndex === 0);
    window.addEventListener("resize", () => placeLens(lens, selected()));
    document.fonts?.ready.then(() => placeLens(lens, selected()));
    select(tabs[0], false);
  });
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
      const text = button.closest(".code").querySelector("pre").textContent;
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

/* The sheen on the glass follows the pointer. */
function startGlassLight() {
  document.querySelectorAll(".glass").forEach((surface) => {
    surface.addEventListener("pointermove", (event) => {
      const box = surface.getBoundingClientRect();
      surface.style.setProperty("--mx", `${event.clientX - box.left}px`);
      surface.style.setProperty("--my", `${event.clientY - box.top}px`);
    });
  });
}

highlightJson();
startLattice();
startParallax();
startHeroProgress();
startTerminal();
startReveals();
startNav();
startCounters();
startTimeline();
startMosca();
startFlow();
startTabs();
startExitCodes();
startCopyButtons();
startGlassLight();
