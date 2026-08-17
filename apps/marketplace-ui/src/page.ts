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
:root {
  --bg: #ffffff;
  --panel: #f7f8fa;
  --panel-edge: #e3e6eb;
  --ink: #14171c;
  --ink-soft: #5b6472;
  --ink-faint: #8a93a3;
  --accent: #1f5fd0;
  --ok: #0f7b4f;
  --ok-bg: #e7f5ee;
  --warn: #8a5a00;
  --warn-bg: #fdf3e0;
  --bad: #a52222;
  --bad-bg: #fdeceb;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #101317;
    --panel: #171b21;
    --panel-edge: #262c35;
    --ink: #e8ecf2;
    --ink-soft: #a3adbb;
    --ink-faint: #77818f;
    --accent: #6ea8ff;
    --ok: #5ed39b;
    --ok-bg: #14301f;
    --warn: #e0b055;
    --warn-bg: #33270f;
    --bad: #ff8f85;
    --bad-bg: #34191a;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif;
  -webkit-font-smoothing: antialiased;
}
.wrap { max-width: 1080px; margin: 0 auto; padding: 28px 20px 72px; }
a { color: var(--accent); }
h1 { font-size: 21px; margin: 0 0 2px; letter-spacing: -0.01em; }
h2 { font-size: 16px; margin: 32px 0 10px; letter-spacing: -0.01em; }
h3 { font-size: 13px; margin: 18px 0 8px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--ink-soft); }
p { margin: 0 0 10px; }
.sub { color: var(--ink-soft); font-size: 13px; margin: 0 0 18px; }
.panel {
  background: var(--panel);
  border: 1px solid var(--panel-edge);
  border-radius: 10px;
  padding: 16px 18px;
  margin: 0 0 14px;
}
.mono { font-family: var(--mono); font-size: 12.5px; }
.faint { color: var(--ink-faint); }
.soft { color: var(--ink-soft); }
table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--panel-edge); vertical-align: top; }
th { font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--ink-soft); font-weight: 600; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.scroll { overflow-x: auto; }
.tag {
  display: inline-block; padding: 1px 7px; border-radius: 999px;
  font-size: 11px; font-weight: 600; letter-spacing: 0.03em; text-transform: uppercase;
}
.tag.ok { background: var(--ok-bg); color: var(--ok); }
.tag.warn { background: var(--warn-bg); color: var(--warn); }
.tag.bad { background: var(--bad-bg); color: var(--bad); }
.tag.flat { background: var(--panel-edge); color: var(--ink-soft); }
.banner {
  border-left: 3px solid var(--warn); background: var(--warn-bg); color: var(--warn);
  padding: 10px 14px; border-radius: 0 8px 8px 0; margin: 0 0 16px; font-size: 13.5px;
}
.banner.bad { border-left-color: var(--bad); background: var(--bad-bg); color: var(--bad); }
.banner.info { border-left-color: var(--accent); background: color-mix(in srgb, var(--accent) 10%, transparent); color: var(--ink); }
.grid { display: grid; gap: 10px; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }
.kv { font-size: 13px; }
.kv dt { color: var(--ink-soft); font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.05em; }
.kv dd { margin: 1px 0 9px; font-family: var(--mono); font-size: 12.5px; word-break: break-all; }
label { display: block; font-size: 12px; color: var(--ink-soft); margin: 0 0 3px; }
input, select, textarea {
  width: 100%; padding: 7px 9px; font: inherit; font-size: 13.5px;
  background: var(--bg); color: var(--ink);
  border: 1px solid var(--panel-edge); border-radius: 6px;
}
textarea { font-family: var(--mono); font-size: 12px; min-height: 150px; }
button {
  padding: 9px 18px; font: inherit; font-weight: 600; font-size: 14px;
  background: var(--accent); color: #fff; border: 0; border-radius: 7px; cursor: pointer;
}
button.ghost { background: transparent; color: var(--accent); border: 1px solid var(--panel-edge); }
.row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-top: 14px; }
.bar { height: 5px; background: var(--panel-edge); border-radius: 3px; overflow: hidden; min-width: 70px; }
.bar > i { display: block; height: 100%; background: var(--accent); }
.rank { font-size: 19px; font-weight: 700; font-variant-numeric: tabular-nums; }
.card { border: 1px solid var(--panel-edge); border-radius: 10px; padding: 14px 16px; margin: 0 0 12px; }
.card.excluded { border-left: 3px solid var(--bad); }
.card.inconclusive { border-left: 3px solid var(--warn); }
.card.eligible { border-left: 3px solid var(--ok); }
.card.unsupported { border-left: 3px solid var(--ink-faint); }
.finding { font-size: 13px; padding: 7px 0; border-bottom: 1px dashed var(--panel-edge); }
.finding:last-child { border-bottom: 0; }
.finding code { font-family: var(--mono); font-size: 12px; font-weight: 600; }
ul.plain { margin: 0; padding-left: 18px; font-size: 13px; }
ul.plain li { margin: 3px 0; }
pre {
  background: var(--bg); border: 1px solid var(--panel-edge); border-radius: 8px;
  padding: 12px; overflow-x: auto; font-family: var(--mono); font-size: 11.5px; margin: 0;
}
nav.tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--panel-edge); margin: 22px 0 0; flex-wrap: wrap; }
nav.tabs a {
  padding: 8px 13px; font-size: 13.5px; text-decoration: none; color: var(--ink-soft);
  border-bottom: 2px solid transparent; margin-bottom: -1px;
}
nav.tabs a[aria-current="page"] { color: var(--ink); border-bottom-color: var(--accent); font-weight: 600; }
footer { margin-top: 44px; padding-top: 16px; border-top: 1px solid var(--panel-edge); font-size: 12px; color: var(--ink-faint); }
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
${input.body}
<footer>
MandateX marketplace &middot; evaluation only. This interface performs no signing,
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
