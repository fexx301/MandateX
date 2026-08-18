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
 * eyeballed. The tightest pair is --ink-faint on --bg at 4.93:1 in light mode
 * and --ink-faint on --surface-2 at 5.17:1 in dark; both clear WCAG AA for body
 * text, which matters because this interface reports refusals and a refusal
 * nobody can read is a refusal nobody can act on.
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
  --ink-faint: #636d7c;
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

  --r-inline: 4px;
  --r-control: 8px;
  --r-surface: 12px;
  --r-pill: 999px;

  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  --ease: cubic-bezier(0.16, 1, 0.3, 1);
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
    --ink-faint: #818fa8;
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
}
::selection { background: var(--accent); color: var(--accent-ink); }

.wrap { max-width: 1060px; margin: 0 auto; padding: 40px 20px 80px; }

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
a { color: var(--accent); text-underline-offset: 2px; text-decoration-thickness: 1px; }
a:hover { text-decoration-thickness: 2px; }
strong { font-weight: 640; }

/* Focus. Previously absent entirely, which made the form unusable by keyboard.
 * :focus-visible rather than :focus so a mouse click does not leave a ring. */
:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
  border-radius: var(--r-inline);
}

.panel {
  background: var(--surface);
  border: 1px solid var(--edge);
  border-radius: var(--r-surface);
  padding: 18px 20px;
  margin: 0 0 16px;
}
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
.stats dd.zero { color: var(--ink-faint); font-weight: 560; }

table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
th, td { text-align: left; padding: 9px 12px; vertical-align: top; }
td { border-top: 1px solid var(--edge); }
th {
  position: sticky; top: 0; z-index: 1;
  background: var(--surface);
  font-size: 10.5px; font-weight: 650; text-transform: uppercase;
  letter-spacing: 0.07em; color: var(--ink-faint);
  border-bottom: 1px solid var(--edge-strong);
  white-space: nowrap;
}
tbody tr:hover { background: var(--surface-2); }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.scroll { overflow-x: auto; border-radius: var(--r-surface); }

.tag {
  display: inline-block; padding: 2px 8px; border-radius: var(--r-pill);
  font-size: 10.5px; font-weight: 650; letter-spacing: 0.05em;
  text-transform: uppercase; border: 1px solid transparent;
  white-space: nowrap;
}
.tag.ok { background: var(--ok-bg); color: var(--ok); border-color: var(--ok-edge); }
.tag.warn { background: var(--warn-bg); color: var(--warn); border-color: var(--warn-edge); }
.tag.bad { background: var(--bad-bg); color: var(--bad); border-color: var(--bad-edge); }
.tag.flat { background: var(--surface-2); color: var(--ink-soft); border-color: var(--edge); }

.banner {
  border: 1px solid var(--warn-edge); border-left-width: 3px;
  background: var(--warn-bg); color: var(--warn);
  padding: 12px 16px; border-radius: var(--r-surface); margin: 0 0 18px;
  font-size: 13.5px;
}
.banner.bad { border-color: var(--bad-edge); background: var(--bad-bg); color: var(--bad); }
.banner.info { border-color: var(--edge); border-left-color: var(--accent); background: var(--accent-soft); color: var(--ink); }
.banner strong { display: block; margin-bottom: 4px; }

/* Page metadata. Columns rather than a run of middot separators: four values
 * strung together on one line with dividers reads as decoration, and the labels
 * are what make an unfamiliar reader able to tell a mandate id from a category. */
.meta {
  display: flex; flex-wrap: wrap; gap: 6px 32px; margin: 0 0 24px;
  padding: 0 0 18px; border-bottom: 1px solid var(--edge);
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

/* Forms. Label above input, never placeholder-as-label. */
label { display: block; font-size: 12px; font-weight: 550; color: var(--ink-soft); margin: 0 0 5px; }
input, select, textarea {
  width: 100%; padding: 9px 11px; font: inherit; font-size: 13.5px;
  background: var(--surface); color: var(--ink);
  border: 1px solid var(--edge-strong); border-radius: var(--r-control);
  transition: border-color 120ms var(--ease), box-shadow 120ms var(--ease);
}
input:hover, select:hover, textarea:hover { border-color: var(--ink-faint); }
select { text-overflow: ellipsis; }
input:focus, select:focus, textarea:focus {
  outline: none; border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-soft);
}
::placeholder { color: var(--ink-faint); opacity: 1; }
textarea { font-family: var(--mono); font-size: 12px; min-height: 150px; line-height: 1.5; }

button {
  padding: 10px 20px; font: inherit; font-weight: 620; font-size: 14px;
  background: var(--accent); color: var(--accent-ink);
  border: 1px solid transparent; border-radius: var(--r-control); cursor: pointer;
  white-space: nowrap;
  transition: filter 120ms var(--ease), transform 60ms var(--ease);
}
button:hover { filter: brightness(1.08); }
/* Tactile push. Section 4.5: the control should feel pressed, not just recoloured. */
button:active { transform: translateY(1px); }
button.ghost {
  background: transparent; color: var(--ink);
  border-color: var(--edge-strong);
}
button.ghost:hover { background: var(--surface-2); filter: none; border-color: var(--ink-faint); }

.row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-top: 18px; }

/* Score indicator with no background track. A filled grey track reads as a
 * dashboard progress bar and implies these values race toward a goal; they are
 * static measurements of one candidate. The rule is the baseline, the ink is
 * the value. */
.bar { min-width: 76px; height: 3px; background: var(--edge); border-radius: var(--r-pill); overflow: hidden; }
.bar > i { display: block; height: 100%; background: var(--accent); border-radius: inherit; }

.rank { font-size: 20px; font-weight: 680; font-variant-numeric: tabular-nums; letter-spacing: -0.02em; }

.card {
  background: var(--surface);
  border: 1px solid var(--edge); border-left-width: 3px; border-left-color: var(--edge-strong);
  border-radius: var(--r-surface); padding: 16px 18px; margin: 0 0 14px;
}
.card.excluded { border-left-color: var(--bad); }
.card.inconclusive { border-left-color: var(--warn); }
.card.eligible { border-left-color: var(--ok); }
.card.unsupported { border-left-color: var(--ink-faint); }

.finding { font-size: 13px; padding: 9px 0; border-top: 1px solid var(--edge); }
.finding:first-of-type { border-top: 0; }
.finding code {
  font-family: var(--mono); font-size: 11.5px; font-weight: 650;
  background: var(--surface-2); border: 1px solid var(--edge);
  border-radius: var(--r-inline); padding: 1px 5px;
}

ul.plain { margin: 6px 0 0; padding-left: 18px; font-size: 13px; }
ul.plain li { margin: 4px 0; }

pre {
  background: var(--surface-2); border: 1px solid var(--edge);
  border-radius: var(--r-surface); padding: 14px; overflow-x: auto;
  font-family: var(--mono); font-size: 11.5px; line-height: 1.55; margin: 0;
}

nav.tabs {
  display: flex; gap: 2px; border-bottom: 1px solid var(--edge);
  margin: 26px 0 0; flex-wrap: wrap;
}
nav.tabs a {
  padding: 9px 14px; font-size: 13.5px; font-weight: 550; text-decoration: none;
  color: var(--ink-soft); border-bottom: 2px solid transparent; margin-bottom: -1px;
  border-radius: var(--r-control) var(--r-control) 0 0;
  transition: color 120ms var(--ease), background 120ms var(--ease);
}
nav.tabs a:hover { color: var(--ink); background: var(--surface-2); }
nav.tabs a[aria-current="page"] { color: var(--ink); border-bottom-color: var(--accent); font-weight: 640; }

/* Brand masthead. The logo sets "Mandate" in the navy and the final X in the
 * blue, so the wordmark here reproduces that split with real type rather than a
 * hand-drawn approximation of the MX monogram. Type recolours correctly in both
 * themes and costs no asset request, which the monogram PNG would not: it has a
 * flat off-white ground baked in and a navy mark that disappears on a dark
 * background. Swap in the mark as an inline SVG when one exists. */
.brand {
  display: flex; align-items: center; gap: 10px;
  margin: 0 0 30px; text-decoration: none; color: var(--ink);
  width: fit-content;
}
.brand-word {
  font-size: 16px; font-weight: 700; letter-spacing: -0.028em;
  font-feature-settings: "ss01";
}
.brand-word i { font-style: normal; color: var(--accent); }
.brand-rule { flex: 0 0 auto; width: 1px; height: 15px; background: var(--edge-strong); }
.brand-tag {
  font-size: 10.5px; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.08em; color: var(--ink-faint);
}

footer {
  margin-top: 52px; padding-top: 18px; border-top: 1px solid var(--edge);
  font-size: 12px; line-height: 1.6; color: var(--ink-faint); max-width: 74ch;
}

@media (max-width: 640px) {
  .wrap { padding: 24px 16px 64px; }
  h1 { font-size: 21px; }
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
