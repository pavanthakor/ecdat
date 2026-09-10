import "@testing-library/jest-dom/vitest";

/**
 * jsdom implements neither of these, and Radix's slider and dialog use both.
 * Shimmed here rather than avoided in the components: the real browser has
 * them, and a test that dodged the primitive would stop testing the thing
 * that ships.
 */
if (!("ResizeObserver" in globalThis)) {
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver;
}

if (!Element.prototype.hasPointerCapture) {
  Element.prototype.hasPointerCapture = () => false;
  Element.prototype.setPointerCapture = () => {};
  Element.prototype.releasePointerCapture = () => {};
}
