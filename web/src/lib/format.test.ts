import { describe, expect, it } from "vitest";

import { formatDateTime, pad2, relativeAge } from "./format";

describe("display formats (ADR-0032)", () => {
  it("formats a stored UTC time the way the tables show it", () => {
    expect(formatDateTime("2026-09-10T06:35:35.824321Z")).toBe("10 Sep 2026 · 06:35");
    expect(formatDateTime(null)).toBe("—");
  });

  it("says how long ago a scan was stored", () => {
    const now = Date.parse("2026-09-10T07:00:00Z");
    expect(relativeAge("2026-09-10T06:48:00Z", now)).toBe("12m ago");
    expect(relativeAge("2026-09-10T01:00:00Z", now)).toBe("6h ago");
    expect(relativeAge("2026-09-01T07:00:00Z", now)).toBe("9d ago");
  });

  it("pads a single-digit count and leaves every other number alone", () => {
    expect(pad2(8)).toBe("08");
    expect(pad2(0)).toBe("00");
    expect(pad2(124)).toBe("124");
  });
});
