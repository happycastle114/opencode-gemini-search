import { test } from "node:test";
import assert from "node:assert/strict";
import { statSync, readFileSync } from "node:fs";
import { stripTerminalControls, validateCitations, shouldHintAutoTrigger } from "../dist/index.js";
import plugin from "../dist/index.js";

test("stripTerminalControls removes CSI sequences", () => {
  assert.equal(stripTerminalControls("\x1b[31mhi\x1b[0m"), "hi");
});

test("stripTerminalControls removes OSC string-mode controls (BEL terminator)", () => {
  assert.equal(stripTerminalControls("\x1b]0;evil\x07x"), "x");
});

test("stripTerminalControls removes OSC string-mode controls (ST terminator)", () => {
  assert.equal(stripTerminalControls("\x1b]0;evil\x1b\\x"), "x");
});

test("stripTerminalControls removes DCS string-mode controls", () => {
  assert.equal(stripTerminalControls("\x1bPdcs payload\x1b\\after"), "after");
});

test("stripTerminalControls removes APC/PM/SOS string-mode controls", () => {
  assert.equal(stripTerminalControls("\x1b_apc\x1b\\\x1b^pm\x1b\\\x1bXsos\x1b\\done"), "done");
});

test("stripTerminalControls removes Fe single-char escapes", () => {
  assert.equal(stripTerminalControls("a\x1bMb"), "ab");
});

test("stripTerminalControls strips C0 control bytes except TAB/LF/CR", () => {
  assert.equal(stripTerminalControls("a\x00b\x07c\tnewline\nkeep"), "abc\tnewline\nkeep");
});

test("validateCitations rejects empty response", () => {
  const r = validateCitations("");
  assert.equal(r.valid, false);
});

test("validateCitations rejects missing ## Sources", () => {
  const r = validateCitations("Answer with [Source](https://example.com).");
  assert.equal(r.valid, false);
  assert.match(r.reason ?? "", /Sources/);
});

test("validateCitations rejects missing inline Source link", () => {
  const r = validateCitations("Answer.\n\n## Sources\n1. https://example.com\n");
  assert.equal(r.valid, false);
  assert.match(r.reason ?? "", /inline/);
});

test("validateCitations accepts compliant response", () => {
  const text = "Node 24 LTS released [Source](https://nodejs.org/en/blog/x).\n\n## Sources\n1. https://nodejs.org/en/blog/x\n";
  const r = validateCitations(text);
  assert.equal(r.valid, true);
});

test("validateCitations rejects citations only inside fenced code blocks", () => {
  const text = "```\n[Source](https://example.com)\n```\n\n## Sources\n1. ex\n";
  const r = validateCitations(text);
  assert.equal(r.valid, false);
});

test("validateCitations rejects citations only inside indented code blocks", () => {
  const text = "para\n\n    [Source](https://example.com)\n\n## Sources\n1. ex\n";
  const r = validateCitations(text);
  assert.equal(r.valid, false);
});

test("validateCitations rejects citations only inside HTML pre block", () => {
  const text = "<pre>[Source](https://example.com)</pre>\n\n## Sources\n1. ex\n";
  const r = validateCitations(text);
  assert.equal(r.valid, false);
});

test("validateCitations rejects citations only inside inline code spans", () => {
  const text = "see `[Source](https://example.com)` here\n\n## Sources\n1. ex\n";
  const r = validateCitations(text);
  assert.equal(r.valid, false);
});

test("validateCitations rejects Markdown image syntax (![Source])", () => {
  const text = "![Source](https://example.com)\n\n## Sources\n1. ex\n";
  const r = validateCitations(text);
  assert.equal(r.valid, false);
});

test("validateCitations accepts http:// scheme", () => {
  const text = "Fact [Source](http://example.com).\n\n## Sources\n1. ex\n";
  assert.equal(validateCitations(text).valid, true);
});

test("validateCitations rejects non-http(s) schemes (javascript:)", () => {
  const text = "[Source](javascript:alert(1))\n\n## Sources\n1. ex\n";
  assert.equal(validateCitations(text).valid, false);
});

test("shouldHintAutoTrigger detects Korean recency keywords", () => {
  assert.equal(shouldHintAutoTrigger("최신 뉴스 알려줘"), true);
  assert.equal(shouldHintAutoTrigger("오늘 날씨"), true);
  assert.equal(shouldHintAutoTrigger("요즘 트렌드"), true);
  assert.equal(shouldHintAutoTrigger("지금 주가"), true);
});

test("shouldHintAutoTrigger detects English recency keywords (case-insensitive)", () => {
  assert.equal(shouldHintAutoTrigger("What's the LATEST version?"), true);
  assert.equal(shouldHintAutoTrigger("recent news please"), true);
  assert.equal(shouldHintAutoTrigger("the current price"), true);
  assert.equal(shouldHintAutoTrigger("Right Now in tokyo"), true);
  assert.equal(shouldHintAutoTrigger("as of today"), true);
});

test("shouldHintAutoTrigger returns false for non-trigger text", () => {
  assert.equal(shouldHintAutoTrigger("How does TCP work?"), false);
  assert.equal(shouldHintAutoTrigger(""), false);
});

test("plugin default export shape", () => {
  assert.equal(typeof plugin, "object");
  assert.equal(plugin.id, "@happycastle/opencode-gemini-search");
  assert.equal(typeof plugin.server, "function");
});

test("plugin.server returns hook bundle with required keys", async () => {
  const hooks = await plugin.server({});
  assert.ok(hooks.tool, "tool registry present");
  assert.ok(hooks.tool.gemini_web_search, "gemini_web_search registered");
  assert.equal(typeof hooks["experimental.chat.system.transform"], "function");
  assert.equal(typeof hooks["chat.message"], "function");
});

test("gemini_web_search tool definition is well-formed", async () => {
  const hooks = await plugin.server({});
  const t = hooks.tool.gemini_web_search;
  assert.equal(typeof t.description, "string");
  assert.ok(t.description.length > 0);
  assert.ok(t.args, "args schema present");
  assert.ok(t.args.query, "query arg present");
  assert.equal(typeof t.execute, "function");
});

test("gemini_web_search rejects empty query without spawning", async () => {
  const hooks = await plugin.server({});
  const t = hooks.tool.gemini_web_search;
  await assert.rejects(
    () => t.execute({ query: "" }, { abort: new AbortController().signal }),
    /non-empty/,
  );
});

test("gemini_web_search rejects oversize query", async () => {
  process.env.GEMINI_SEARCH_MAX_QUERY_CHARS = "100";
  try {
    const hooks = await plugin.server({});
    const t = hooks.tool.gemini_web_search;
    const big = "x".repeat(200);
    await assert.rejects(
      () => t.execute({ query: big }, { abort: new AbortController().signal }),
      /MAX_QUERY_CHARS/,
    );
  } finally {
    delete process.env.GEMINI_SEARCH_MAX_QUERY_CHARS;
  }
});

test("experimental.chat.system.transform appends auto-trigger note", async () => {
  const hooks = await plugin.server({});
  const output = { system: ["existing"] };
  await hooks["experimental.chat.system.transform"]({}, output);
  assert.equal(output.system.length, 2);
  assert.match(output.system[1], /Web Search Tool Available/);
  assert.match(output.system[1], /gemini_web_search/);
});

test("chat.message hook is no-op when debug env is unset", async () => {
  delete process.env.OPENCODE_GEMINI_SEARCH_DEBUG;
  const hooks = await plugin.server({});
  const errors = [];
  const original = console.error;
  console.error = (...a) => errors.push(a);
  try {
    await hooks["chat.message"](
      {},
      { message: { id: "m1" }, parts: [{ type: "text", text: "최신 뉴스" }] },
    );
  } finally {
    console.error = original;
  }
  assert.equal(errors.length, 0);
});

test("chat.message hook logs when debug env is set and trigger keyword present", async () => {
  process.env.OPENCODE_GEMINI_SEARCH_DEBUG = "1";
  const hooks = await plugin.server({});
  const errors = [];
  const original = console.error;
  console.error = (...a) => errors.push(a.join(" "));
  try {
    await hooks["chat.message"](
      {},
      { message: { id: "m1" }, parts: [{ type: "text", text: "오늘 환율" }] },
    );
  } finally {
    console.error = original;
    delete process.env.OPENCODE_GEMINI_SEARCH_DEBUG;
  }
  assert.equal(errors.length, 1);
  assert.match(errors[0], /m1/);
});

test("chat.message hook ignores non-text parts safely", async () => {
  process.env.OPENCODE_GEMINI_SEARCH_DEBUG = "1";
  const hooks = await plugin.server({});
  const errors = [];
  const original = console.error;
  console.error = (...a) => errors.push(a.join(" "));
  try {
    await hooks["chat.message"](
      {},
      {
        message: { id: "m2" },
        parts: [
          { type: "tool", id: "x" },
          { type: "text", text: "static topic" },
        ],
      },
    );
  } finally {
    console.error = original;
    delete process.env.OPENCODE_GEMINI_SEARCH_DEBUG;
  }
  assert.equal(errors.length, 0);
});

test("source file is loadable as an ES module", () => {
  const stat = statSync("./dist/index.js");
  assert.ok(stat.size > 0);
  const body = readFileSync("./dist/index.js", "utf8");
  assert.match(body, /import .* from ["']node:child_process["']/);
  assert.match(body, /export default/);
});
