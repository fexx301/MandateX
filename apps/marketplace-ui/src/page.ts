import { html, raw, render, type Html } from "./html.js";

/**
 * Page shell.
 *
 * Inline CSS, no external stylesheet, no font fetch, no client framework, no
 * bundler. The whole point is that the deployed artifact is a Node process
 * serving strings: there is no build step that can fail at deploy time and no
 * `npm install` on the critical path to a judge clicking a link.
 *
 * There is a small amount of client JavaScript, for `<details>`-free tab
 * switching and nothing else. Every screen renders fully server-side and works
 * with JavaScript disabled; the script only reduces clicks.
 */

const STYLES = `
/* Tokens.
 *
 * --accent and --ink are the brand's own colours, sampled from the MandateX
 * logo rather than approximated: #0057fd is the blue of the X, #051229 the navy
 * of the M. Dark mode is grounded in that same navy instead of a generic slate,
 * so the product reads as one brand in both themes, and the dark accent is the
 * brand blue lifted to #6b9dff because #0057fd does not carry enough luminance
 * against a near-black ground.
 *
 * One accent, one neutral temperature (cool), one radius rule. Every pair below
 * was contrast-checked against the surface it actually sits on rather than
 * eyeballed, and re-checked after the ambient bloom was added — because the bloom
 * composites behind any text that is not inside a panel, which moved the tightest
 * pair. Measured worst cases, against the fully-stacked bloom rather than the
 * plain page:
 *
 *   light  --ink-faint on stacked bloom  4.78:1
 *   dark   --ink-faint on stacked bloom  4.59:1
 *   light  --ink-faint on --surface      6.65:1
 *   dark   --ink-faint on --surface      6.28:1
 *
 * All clear WCAG AA for body text, which matters because this interface reports
 * refusals and a refusal nobody can read is a refusal nobody can act on. Panels
 * stay fully opaque precisely so the bloom cannot erode the ratios inside them.
 *
 * Neither mode uses pure #ffffff or #000000. Pure values flatten the surface
 * hierarchy, and the hierarchy is doing real work here: panels are raised by
 * being lighter than the page, not by casting a shadow.
 *
 * RADIUS RULE, applied everywhere with no exceptions:
 *   --r-inline     inline chips and focus rings, which sit inside a line of text
 *   --r-control    interactive things you click or type into
 *   --r-surface    containers that hold content
 *   --r-pill       status tags only
 */
:root {
  --bg: #f7f8fa;
  --surface: #ffffff;
  --surface-2: #f1f3f7;
  --edge: #e3e7ee;
  --edge-strong: #cdd4e0;
  --ink: #051229;
  --ink-soft: #46536b;
  --ink-faint: #555d69;
  --accent: #0057fd;
  --accent-ink: #ffffff;
  --accent-soft: #e8f0ff;
  --ok: #06683f;
  --ok-bg: #e8f7ef;
  --ok-edge: #a8e0c2;
  --warn: #8a4c05;
  --warn-bg: #fdf4e3;
  --warn-edge: #f0cf8e;
  --bad: #a81f16;
  --bad-bg: #fdeeec;
  --bad-edge: #f3bdb7;

  /* RADIUS RULE, plus the two concentric tiers the bezel needs. --r-core is
   * derived, never hand-picked: a nested container whose radius is not
   * (outer - padding) produces curves that visibly disagree at the corner. */
  --r-inline: 4px;
  --r-control: 8px;
  --r-surface: 12px;
  --r-shell: 16px;
  --r-core: calc(var(--r-shell) - 5px);
  --r-pill: 999px;

  /* Type. Roboto and Inter are deliberately absent: both are banned by the
   * design directives, and Roboto was previously named third in this stack.
   * Outfit was the assigned face but cannot be used — self-hosting it means
   * committing a binary and a CDN link means an external request on a page that
   * must render with no network beyond its own origin. So this is a curated
   * system stack that reaches for the best grotesk actually installed on each
   * platform before falling back. system-ui sits late rather than first for
   * exactly that reason. */
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  --sans: "SF Pro Text", -apple-system, "Segoe UI Variable Text", "Segoe UI",
    ui-sans-serif, system-ui, sans-serif;

  /* Motion. Both curves decelerate hard and never accelerate at the end, which
   * is what makes a transition read as mass settling rather than as a tween.
   * No linear, no ease-in-out anywhere in this file. */
  --ease: cubic-bezier(0.16, 1, 0.3, 1);
  --ease-hard: cubic-bezier(0.32, 0.72, 0, 1);

  /* Hairlines as alpha over the surface, not flat grey. A 1px #e3e7ee line is
   * the single most reliable tell of an unconsidered interface: it reads as a
   * drawn border instead of as an edge where two planes meet. */
  --hair: color-mix(in oklab, var(--ink) 9%, transparent);
  --hair-strong: color-mix(in oklab, var(--ink) 15%, transparent);
  --sheen: color-mix(in oklab, #ffffff 78%, transparent);

  /* Diffused ambient depth. Wide, low-alpha, tinted with the brand navy rather
   * than black, so a raised surface looks lit from above instead of stamped
   * onto the page. */
  --shadow-raised:
    0 1px 2px -1px color-mix(in oklab, var(--ink) 12%, transparent),
    0 10px 30px -18px color-mix(in oklab, var(--ink) 30%, transparent);
  --shadow-float:
    0 2px 4px -2px color-mix(in oklab, var(--ink) 14%, transparent),
    0 18px 48px -24px color-mix(in oklab, var(--ink) 34%, transparent);

  /* Bloom strength is not a taste setting, it is a contrast budget. These three
   * gradient layers can coincide at a peak, and the whole pseudo-element is then
   * multiplied by its own 0.5 opacity, so the worst realistic composite behind
   * text is accent-over-violet-over-accent at 7%/6%/7%. Measured, that lands the
   * page background at #d0dafa, where --ink-faint reads 4.78:1 and clears AA with
   * margin. Raising these values pushes body text under 4.5:1 — the previous
   * palette failed at exactly this, at 4.17:1, and it is invisible until someone
   * tries to read a refusal against the bloom. */
  --bloom-a: color-mix(in oklab, var(--accent) 14%, transparent);
  --bloom-b: color-mix(in oklab, #7d5cff 12%, transparent);
  --grain: 0.035;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #050b18;
    --surface: #0a1526;
    --surface-2: #0f1d33;
    --edge: #172740;
    --edge-strong: #223451;
    --ink: #e8eefb;
    --ink-soft: #a3b2cc;
    --ink-faint: #8b98b0;
    --accent: #6b9dff;
    --accent-ink: #051229;
    --accent-soft: #10203c;
    --ok: #55dfa0;
    --ok-bg: #082418;
    --ok-edge: #10462e;
    --warn: #f5b544;
    --warn-bg: #2a1e07;
    --warn-edge: #4a350f;
    --bad: #ff9187;
    --bad-bg: #2c1310;
    --bad-edge: #4c1e19;

    /* Dark inverts the sheen: an inset highlight has to be white at very low
     * alpha on a dark plane, and the ambient shadow goes near-black because a
     * navy-tinted shadow on a navy ground is invisible. The bloom is allowed
     * more presence here, since a dark page can carry colour that a light one
     * would look bruised by. */
    --hair: color-mix(in oklab, #ffffff 11%, transparent);
    --hair-strong: color-mix(in oklab, #ffffff 18%, transparent);
    --sheen: color-mix(in oklab, #ffffff 9%, transparent);
    --shadow-raised:
      0 1px 2px -1px rgba(0, 0, 0, 0.5),
      0 12px 34px -20px rgba(0, 0, 0, 0.7);
    --shadow-float:
      0 2px 6px -2px rgba(0, 0, 0, 0.55),
      0 22px 56px -26px rgba(0, 0, 0, 0.8);
    /* Same contrast budget as light mode, recomputed for this ground. A dark page
     * can carry more colour before text suffers, but not unlimited: at 26%/22%
     * --ink-faint fell to 3.56:1, well under AA. 20%/17% with the lifted faint
     * lands it at 4.59:1. */
    --bloom-a: color-mix(in oklab, var(--accent) 20%, transparent);
    --bloom-b: color-mix(in oklab, #8f6cff 17%, transparent);
    --grain: 0.05;
  }
}

* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font: 15px/1.6 var(--sans);
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
  font-feature-settings: "kern" 1, "liga" 1, "cv11" 1;
  font-optical-sizing: auto;
}

/* Ambient surface: a layered conic bloom and a film grain, both on fixed
 * pointer-events-none layers.
 *
 * Fixed rather than attached to .wrap on purpose. A blurred or noisy layer
 * inside a scrolling container repaints on every frame of a scroll; a fixed
 * layer is composited once. Neither layer ever intercepts a click, and neither
 * sits above content — the bloom is behind everything at z-index 0 with content
 * lifted to 1, so no text is ever rendered on top of a moving gradient.
 *
 * The bloom is what keeps the page from reading as a flat grey document without
 * spending contrast to do it: panels stay fully opaque, so every text/surface
 * ratio measured for the palette is preserved exactly. The colour is only ever
 * visible in the gutter around and behind the content column. */
body::before {
  content: "";
  position: fixed;
  inset: -20vmax -10vmax auto -10vmax;
  height: 90vmax;
  z-index: 0;
  pointer-events: none;
  background:
    radial-gradient(42vmax 32vmax at 18% 8%, var(--bloom-a), transparent 68%),
    radial-gradient(38vmax 30vmax at 88% 2%, var(--bloom-b), transparent 66%),
    conic-gradient(from 210deg at 62% 12%, var(--bloom-a), transparent 30%, var(--bloom-b), transparent 62%);
  filter: blur(58px) saturate(115%);
  opacity: 0.5;
}

/* Grain via an inline SVG turbulence data URI. Inline, so it is not a network
 * request; the whole point of this page is that it fetches nothing. */
body::after {
  content: "";
  position: fixed;
  inset: 0;
  z-index: 0;
  pointer-events: none;
  opacity: var(--grain);
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='140' height='140'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.82' numOctaves='3' stitchTiles='stitch'/%3E%3CfeColorMatrix type='saturate' values='0'/%3E%3C/filter%3E%3Crect width='140' height='140' filter='url(%23n)'/%3E%3C/svg%3E");
}

::selection { background: var(--accent); color: var(--accent-ink); }

.wrap { position: relative; z-index: 1; max-width: 1060px; margin: 0 auto; padding: 40px 20px 80px; }

/* Hierarchy comes from weight and colour, not raw scale. A console that shouts
 * its headings competes with the data, which is the only thing worth reading. */
h1 {
  font-size: 23px; font-weight: 640; line-height: 1.25;
  letter-spacing: -0.021em; margin: 0 0 4px; text-wrap: balance;
}
h2 {
  font-size: 16.5px; font-weight: 620; line-height: 1.3;
  letter-spacing: -0.014em; margin: 34px 0 12px; text-wrap: balance;
}
h3 {
  font-size: 12px; font-weight: 650; margin: 20px 0 8px;
  text-transform: uppercase; letter-spacing: 0.07em; color: var(--ink-soft);
}
p { margin: 0 0 10px; max-width: 74ch; text-wrap: pretty; }
.sub { color: var(--ink-soft); font-size: 13.5px; margin: 0 0 22px; max-width: 74ch; }
/* Scrub-underline. The rule grows from the leading edge on hover instead of the
 * underline thickening, which is the browser default and reads as a text-decoration
 * change rather than as a deliberate response. scaleX only — no layout. */
a {
  position: relative;
  color: var(--accent);
  text-decoration: none;
}
a::after {
  content: "";
  position: absolute;
  left: 0; right: 0; bottom: -2px;
  height: 1.5px;
  background: currentColor;
  border-radius: var(--r-pill);
  transform: scaleX(0);
  transform-origin: left center;
  transition: transform 380ms var(--ease-hard);
}
a:hover::after, a:focus-visible::after { transform: scaleX(1); }
/* Links inside prose keep a persistent underline: in a paragraph, colour alone
 * is not a sufficient affordance, and a link you have to hover to discover is a
 * link most readers never find. */
p a::after, li a::after, footer a::after, .soft a::after { transform: scaleX(1); }
p a:hover::after, li a:hover::after, footer a:hover::after { height: 2.5px; }
strong { font-weight: 640; }

/* Focus. Previously absent entirely, which made the form unusable by keyboard.
 * :focus-visible rather than :focus so a mouse click does not leave a ring.
 * Two rings, not one: a light gap ring separates the accent ring from whatever
 * the control sits on, so it stays legible against both the page and a panel. */
:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
  border-radius: var(--r-inline);
  box-shadow: 0 0 0 5px color-mix(in oklab, var(--accent) 18%, transparent);
}

/* Double-bezel. The element itself is the outer shell — a tray, one step darker
 * than the plate it holds — and ::before is the inner core, inset by exactly the
 * bezel gap with a radius of (shell - gap) so the two curves stay concentric. A
 * nested radius picked by hand instead of derived is visible at the corner as
 * two curves disagreeing, which is why --r-core is a calc.
 *
 * Content is not wrapped in an extra div: the shell's padding is the bezel gap
 * plus the content inset, so the core plane lands between them. That keeps the
 * markup identical, which matters because the suite asserts on it. */
.panel {
  position: relative;
  background: var(--surface-2);
  border: 1px solid var(--hair);
  border-radius: var(--r-shell);
  padding: 24px 26px;
  margin: 0 0 16px;
  box-shadow: var(--shadow-raised);
}
.panel::before {
  content: "";
  position: absolute;
  inset: 6px;
  border-radius: var(--r-core);
  background: var(--surface);
  border: 1px solid var(--hair);
  box-shadow: inset 0 1px 0 var(--sheen);
  pointer-events: none;
}
.panel > * { position: relative; z-index: 1; }
.mono { font-family: var(--mono); font-size: 12.5px; font-variant-numeric: tabular-nums; }
.faint { color: var(--ink-faint); }
.soft { color: var(--ink-soft); }

/* Summary readout. Seven counts, so seven cells: the grid is sized to fit them
 * on one row at desktop and wrap cleanly rather than leaving a ragged gap. The
 * number carries the tone as colour; it is a measurement, not a badge, so it is
 * not wrapped in a pill. */
.stats {
  display: grid; gap: 4px 18px;
  grid-template-columns: repeat(auto-fit, minmax(116px, 1fr));
  margin: 0;
}
.stats > div { padding: 2px 0; }
.stats dt {
  font-size: 10.5px; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.07em; color: var(--ink-faint); margin: 0 0 3px;
  /* Two lines reserved for every label, because one of them ("Rejected at
   * verification") wraps and the rest do not. Without the reservation that one
   * cell pushes its number a line lower than the other six, and a row of counts
   * that do not share a baseline reads as broken rather than as dense. */
  line-height: 1.25; min-height: 2.5em;
}
.stats dd {
  margin: 0; font-size: 25px; font-weight: 660; line-height: 1.05;
  font-variant-numeric: tabular-nums; letter-spacing: -0.02em;
}
.stats dd.ok { color: var(--ok); }
.stats dd.warn { color: var(--warn); }
.stats dd.bad { color: var(--bad); }
.stats dd.flat { color: var(--ink); }
/* A zero is dimmed rather than coloured. Seven identically-weighted numbers make
 * the reader hunt for the ones that matter; dimming the empty ones means the
 * populated buckets are what the eye lands on. */
.stats dd.zero { color: var(--ink-faint); font-weight: 560; }

/* Tables sit on the panel core, so their rules are hairlines rather than drawn
 * grey lines. The sticky header gets the core background plus a hairline under
 * it, so a scrolled row never bleeds through it. */
table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
th, td { text-align: left; padding: 10px 13px; vertical-align: top; }
td { border-top: 1px solid var(--hair); }
th {
  position: sticky; top: 0; z-index: 1;
  background: var(--surface);
  font-size: 10.5px; font-weight: 650; text-transform: uppercase;
  letter-spacing: 0.07em; color: var(--ink-faint);
  border-bottom: 1px solid var(--hair-strong);
  white-space: nowrap;
}
tbody tr { transition: background 200ms var(--ease-hard); }
tbody tr:hover { background: color-mix(in oklab, var(--accent) 6%, transparent); }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
/* Wide tables scroll inside their own box, never the page. The inset ring is what
 * signals the box is scrollable without adding a visible scrollbar gutter. */
.scroll {
  overflow-x: auto;
  border-radius: var(--r-core);
  box-shadow: inset 0 0 0 1px var(--hair);
  overscroll-behavior-x: contain;
}

.tag {
  display: inline-block; padding: 2px 8px; border-radius: var(--r-pill);
  font-size: 10.5px; font-weight: 650; letter-spacing: 0.05em;
  text-transform: uppercase; border: 1px solid transparent;
  white-space: nowrap;
}
.tag.ok { background: var(--ok-bg); color: var(--ok); border-color: var(--ok-edge); }
.tag.warn { background: var(--warn-bg); color: var(--warn); border-color: var(--warn-edge); }
.tag.bad { background: var(--bad-bg); color: var(--bad); border-color: var(--bad-edge); }
.tag.flat { background: var(--surface-2); color: var(--ink-soft); border-color: var(--hair-strong); }

/* Banners carry refusals, so they get real presence: a 3px accent rail, an inset
 * sheen and an ambient shadow. This is the one component where visual weight is
 * a correctness property — a warning that reads as decoration gets skipped. */
.banner {
  position: relative;
  border: 1px solid var(--warn-edge); border-left-width: 3px;
  background: var(--warn-bg); color: var(--warn);
  padding: 14px 18px; border-radius: var(--r-surface); margin: 0 0 18px;
  font-size: 13.5px;
  box-shadow: inset 0 1px 0 color-mix(in oklab, #ffffff 22%, transparent), var(--shadow-raised);
}
.banner.bad { border-color: var(--bad-edge); background: var(--bad-bg); color: var(--bad); }
.banner.info { border-color: var(--hair); border-left-color: var(--accent); background: var(--accent-soft); color: var(--ink); }
.banner strong { display: block; margin-bottom: 4px; }

/* Page metadata. Columns rather than a run of middot separators: four values
 * strung together on one line with dividers reads as decoration, and the labels
 * are what make an unfamiliar reader able to tell a mandate id from a category. */
.meta {
  display: flex; flex-wrap: wrap; gap: 6px 32px; margin: 0 0 24px;
  padding: 0 0 18px; border-bottom: 1px solid var(--hair);
}
.meta dt {
  font-size: 10.5px; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.07em; color: var(--ink-faint); margin: 0 0 2px;
}
.meta dd { margin: 0; font-size: 13px; color: var(--ink); }

.grid { display: grid; gap: 14px; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); align-items: start; }
/* The category option labels name a protocol as well as a strategy, so they are
 * wider than one grid track. Given two tracks they fit; the ellipsis below is the
 * fallback for anything longer still, because a select that clips mid-word makes
 * the reader guess which option is selected. */
.grid > .span-2 { grid-column: span 2; }
@media (max-width: 640px) { .grid > .span-2 { grid-column: span 1; } }

.kv { font-size: 13px; margin: 0; }
.kv dt {
  color: var(--ink-faint); font-size: 10.5px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.07em;
}
.kv dd {
  margin: 2px 0 10px; font-family: var(--mono); font-size: 12.5px;
  overflow-wrap: anywhere; color: var(--ink);
}

/* Forms. Label above input, never placeholder-as-label.
 *
 * Inputs get the bezel treatment inverted: a field is a recess, not a raised
 * plate, so the inset shadow runs dark-at-the-top instead of a bright sheen. That
 * is the correct physical metaphor and it makes a text field read as somewhere to
 * put something rather than as a card with a border. */
label { display: block; font-size: 12px; font-weight: 550; color: var(--ink-soft); margin: 0 0 5px; }
input, select, textarea {
  width: 100%; padding: 11px 13px; font: inherit; font-size: 13.5px;
  background: var(--surface-2); color: var(--ink);
  border: 1px solid var(--hair-strong); border-radius: var(--r-control);
  box-shadow:
    inset 0 1px 2px color-mix(in oklab, var(--ink) 8%, transparent),
    inset 0 0 0 1px color-mix(in oklab, var(--ink) 2%, transparent);
  transition:
    border-color 240ms var(--ease-hard),
    box-shadow 240ms var(--ease-hard),
    background 240ms var(--ease-hard);
}
input:hover, select:hover, textarea:hover { border-color: var(--ink-faint); }
select { text-overflow: ellipsis; }
input:focus, select:focus, textarea:focus {
  outline: none; border-color: var(--accent);
  background: var(--surface);
  box-shadow:
    inset 0 1px 2px color-mix(in oklab, var(--ink) 5%, transparent),
    0 0 0 4px color-mix(in oklab, var(--accent) 16%, transparent);
}
::placeholder { color: var(--ink-faint); opacity: 1; }
textarea { font-family: var(--mono); font-size: 12px; min-height: 150px; line-height: 1.5; }

/* Buttons. Sheen on top, ambient shadow below, and a press that actually
 * compresses — scale plus a 1px drop, so the control feels like it has mass.
 * Contrast is not left to chance: --accent-ink is white on the light accent and
 * the brand navy on the lifted dark accent, both measured below AA thresholds
 * for large text with room to spare. */
button {
  position: relative;
  overflow: hidden;
  padding: 12px 26px; font: inherit; font-weight: 620; font-size: 14px;
  background: var(--accent); color: var(--accent-ink);
  border: 1px solid transparent; border-radius: var(--r-pill); cursor: pointer;
  white-space: nowrap;
  box-shadow: inset 0 1px 0 color-mix(in oklab, #ffffff 26%, transparent), var(--shadow-raised);
  transition:
    filter 200ms var(--ease-hard),
    transform 140ms var(--ease-hard),
    box-shadow 200ms var(--ease-hard);
}
button::after {
  content: "";
  position: absolute; inset: 0;
  background: linear-gradient(100deg, color-mix(in oklab, #ffffff 26%, transparent), transparent 46%);
  opacity: 0;
  transform: translate3d(-30%, 0, 0);
  transition: opacity 380ms var(--ease-hard), transform 560ms var(--ease-hard);
}
button:hover { filter: brightness(1.06); box-shadow: inset 0 1px 0 color-mix(in oklab, #ffffff 30%, transparent), var(--shadow-float); }
button:hover::after { opacity: 1; transform: translate3d(0, 0, 0); }
button:active { transform: translate3d(0, 1px, 0) scale(0.985); }
button.ghost {
  background: transparent; color: var(--ink);
  border-color: var(--hair-strong);
  box-shadow: none;
}
button.ghost:hover { background: var(--surface-2); filter: none; border-color: var(--ink-faint); box-shadow: var(--shadow-raised); }

.row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-top: 18px; }

/* Score indicator with no background track. A filled grey track reads as a
 * dashboard progress bar and implies these values race toward a goal; they are
 * static measurements of one candidate. The rule is the baseline, the ink is
 * the value. */
.bar { min-width: 76px; height: 3px; background: var(--hair); border-radius: var(--r-pill); overflow: hidden; }
.bar > i { display: block; height: 100%; background: var(--accent); border-radius: inherit; }

.rank { font-size: 20px; font-weight: 680; font-variant-numeric: tabular-nums; letter-spacing: -0.02em; }

/* Candidate cards carry the same bezel, plus an edge-sweep on hover: a soft
 * highlight travels in from the leading edge rather than the whole surface
 * changing colour. Transform and opacity only, so it composites on the GPU and
 * never triggers layout.
 *
 * The status colour stays on the OUTER shell's left edge, at full strength. That
 * stripe is how a reader finds the excluded candidates while scanning, so it is
 * the one thing in this file that visual polish is not allowed to soften. */
.card {
  position: relative;
  overflow: hidden;
  background: var(--surface-2);
  border: 1px solid var(--hair);
  border-left-width: 3px;
  border-left-color: var(--hair-strong);
  border-radius: var(--r-shell);
  padding: 22px 24px;
  margin: 0 0 14px;
  box-shadow: var(--shadow-raised);
  transition: box-shadow 320ms var(--ease-hard), transform 320ms var(--ease-hard);
}
.card::before {
  content: "";
  position: absolute;
  inset: 6px;
  border-radius: var(--r-core);
  background: var(--surface);
  border: 1px solid var(--hair);
  box-shadow: inset 0 1px 0 var(--sheen);
  pointer-events: none;
}
/* The sweep. Sits above the core plane but below content, and is clipped by the
 * card's overflow so it never bleeds past the bezel. */
.card::after {
  content: "";
  position: absolute;
  inset: 6px;
  border-radius: var(--r-core);
  pointer-events: none;
  opacity: 0;
  background: linear-gradient(
    100deg,
    color-mix(in oklab, var(--accent) 14%, transparent) 0%,
    transparent 42%
  );
  transform: translate3d(-24%, 0, 0);
  transition: opacity 420ms var(--ease-hard), transform 620ms var(--ease-hard);
}
.card:hover { box-shadow: var(--shadow-float); transform: translate3d(0, -1px, 0); }
.card:hover::after { opacity: 1; transform: translate3d(0, 0, 0); }
.card > * { position: relative; z-index: 1; }
.card.excluded { border-left-color: var(--bad); }
.card.inconclusive { border-left-color: var(--warn); }
.card.eligible { border-left-color: var(--ok); }
.card.unsupported { border-left-color: var(--ink-faint); }

.finding { font-size: 13px; padding: 10px 0; border-top: 1px solid var(--hair); }
.finding:first-of-type { border-top: 0; }
.finding code {
  font-family: var(--mono); font-size: 11.5px; font-weight: 650;
  background: var(--surface-2); border: 1px solid var(--hair);
  border-radius: var(--r-inline); padding: 1px 5px;
}

ul.plain { margin: 6px 0 0; padding-left: 18px; font-size: 13px; }
ul.plain li { margin: 4px 0; }

pre {
  background: var(--surface-2); border: 1px solid var(--hair);
  border-radius: var(--r-surface); padding: 14px; overflow-x: auto;
  font-family: var(--mono); font-size: 11.5px; line-height: 1.55; margin: 0;
}

nav.tabs {
  display: flex; gap: 2px; border-bottom: 1px solid var(--hair);
  margin: 26px 0 0; flex-wrap: wrap;
}
nav.tabs a {
  position: relative;
  padding: 10px 15px; font-size: 13.5px; font-weight: 550; text-decoration: none;
  color: var(--ink-soft); margin-bottom: -1px;
  border-radius: var(--r-control) var(--r-control) 0 0;
  transition: color 240ms var(--ease-hard), background 240ms var(--ease-hard);
}
/* The tab indicator is the same scrub-underline, re-anchored to the bottom edge
 * so it reads as a tab rail rather than a text underline. */
nav.tabs a::after {
  left: 6px; right: 6px; bottom: 0; height: 2px;
  background: var(--accent);
  border-radius: var(--r-pill) var(--r-pill) 0 0;
  transform: scaleX(0);
}
nav.tabs a:hover { color: var(--ink); background: color-mix(in oklab, var(--ink) 4%, transparent); }
nav.tabs a:hover::after { transform: scaleX(1); }
nav.tabs a[aria-current="page"] { color: var(--ink); font-weight: 640; }
nav.tabs a[aria-current="page"]::after { transform: scaleX(1); }

/* Brand masthead. The logo sets "Mandate" in the navy and the final X in the
 * blue, so the wordmark here reproduces that split with real type rather than a
 * hand-drawn approximation of the MX monogram. Type recolours correctly in both
 * themes and costs no asset request, which the monogram PNG would not: it has a
 * flat off-white ground baked in and a navy mark that disappears on a dark
 * background. Swap in the mark as an inline SVG when one exists. */
.brand {
  display: flex; align-items: center; gap: 11px;
  margin: 0 0 32px; text-decoration: none; color: var(--ink);
  width: fit-content;
}
/* The wordmark is a link, so it inherits the scrub-underline; suppress it here
 * because a rule under the logotype reads as a mistake rather than a hover. */
.brand::after { display: none; }
.brand-word {
  font-size: 17px; font-weight: 700; letter-spacing: -0.03em;
  font-feature-settings: "ss01";
}
.brand-word i {
  font-style: normal;
  color: var(--accent);
  /* The X is the brand's own mark, so it gets the one gradient in the interface. */
  background: linear-gradient(135deg, var(--accent), color-mix(in oklab, var(--accent) 55%, #7d5cff));
  -webkit-background-clip: text; background-clip: text;
  -webkit-text-fill-color: transparent;
}
.brand-rule { flex: 0 0 auto; width: 1px; height: 16px; background: var(--hair-strong); }
.brand-tag {
  font-size: 10.5px; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.09em; color: var(--ink-faint);
}

footer {
  margin-top: 56px; padding-top: 20px; border-top: 1px solid var(--hair);
  font-size: 12px; line-height: 1.65; color: var(--ink-faint); max-width: 74ch;
}

@media (max-width: 640px) {
  .wrap { padding: 24px 16px 64px; }
  h1 { font-size: 21px; }
  /* Padding is larger than the pre-bezel values because the shell now spends 6px
   * of it on the bezel gap before content begins. */
  .panel { padding: 20px 18px; }
  .card { padding: 18px 16px; }
  .stats { grid-template-columns: repeat(auto-fit, minmax(96px, 1fr)); }
  .stats dd { font-size: 21px; }
  .row > button { width: 100%; }
}

/* Motion here is confined to hover, focus and press feedback, so honouring this
 * costs nothing and removes it for anyone who asked for that. */
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { transition: none !important; animation: none !important; }
}
`;

export function page(input: {
  readonly title: string;
  readonly body: Html;
}): string {
  return (
    "<!doctype html>" +
    render(html`<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="robots" content="noindex" />
<title>${input.title}</title>
<style>${raw(STYLES)}</style>
</head>
<body>
<div class="wrap">
<a class="brand" href="/">
  <span class="brand-word">Mandate<i>X</i></span>
  <span class="brand-rule" aria-hidden="true"></span>
  <span class="brand-tag">Agent marketplace</span>
</a>
${input.body}
<footer>
MandateX marketplace, evaluation only. This interface performs no signing,
funding, settlement or broadcasting, and holds no key. Every verdict shown is
computed by Marketplace Core inside the marketplace API and rendered here
unchanged.
</footer>
</div>
</body>
</html>`)
  );
}

/**
 * In-page section nav for the result page.
 *
 * Anchors rather than routes, because separate routes would each need their own
 * evaluation. Freshness verdicts are clock-dependent, so two evaluations seconds
 * apart can disagree — a candidate could read eligible under "Comparison" and
 * excluded under "Permissions". One evaluation renders one page.
 */
export function sectionNav(): Html {
  const items: readonly (readonly [string, string])[] = [
    ["#ranked", "Ranked"],
    ["#basis", "Ranking basis"],
    ["#permissions", "Permissions"],
    ["#activation", "Activation"],
    ["#receipt", "Receipt"],
  ];
  return html`<nav class="tabs">
    ${items.map(([href, label]) => html`<a href="${href}">${label}</a>`)}
  </nav>`;
}
