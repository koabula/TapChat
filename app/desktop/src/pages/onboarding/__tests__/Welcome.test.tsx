import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import Welcome from "../Welcome";

describe("onboarding welcome", () => {
  it("separates local profile recovery from opening an existing profile", () => {
    const html = renderToStaticMarkup(
      <MemoryRouter>
        <Welcome />
      </MemoryRouter>,
    );

    expect(html).toContain("Recover Identity on This Device");
    expect(html).not.toContain("Recover Existing Identity");
  });
});
