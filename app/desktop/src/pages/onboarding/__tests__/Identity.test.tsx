import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import Identity from "../Identity";

describe("identity onboarding", () => {
  it("explains that recovery creates local storage without restoring message history", () => {
    const html = renderToStaticMarkup(
      <MemoryRouter initialEntries={["/onboarding/identity?mode=recover"]}>
        <Identity />
      </MemoryRouter>,
    );

    expect(html).toContain("Create a Local Profile for Recovery");
    expect(html).toContain("does not restore local message history");
  });
});
