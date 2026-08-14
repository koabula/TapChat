import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import ImageGrid from "@/components/ImageGrid";

describe("ImageGrid", () => {
  it("reserves a responsive visible box before receiver media loads", () => {
    const html = renderToStaticMarkup(
      <ImageGrid
        items={[{
          messageId: "msg:photo",
          conversationId: "conversation:1",
          mimeType: "image/jpeg",
          width: 1600,
          height: 900,
          previewAvailable: true,
          attachmentState: "published",
        }]}
        onImageClick={() => undefined}
      />,
    );

    expect(html).toContain("w-[min(22rem,72vw)]");
    expect(html).toContain("min-h-24");
    expect(html).toContain("aspect-ratio:1.7777777777777777");
  });
});
