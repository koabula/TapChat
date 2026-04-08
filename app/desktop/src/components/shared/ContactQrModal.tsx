import { useEffect, useState } from "react";
import QRCode from "qrcode";

export default function ContactQrModal({
  title,
  value,
  onClose,
}: {
  title: string;
  value: string;
  onClose: () => void;
}) {
  const [svg, setSvg] = useState("");

  useEffect(() => {
    let active = true;
    void QRCode.toString(value, {
      type: "svg",
      margin: 1,
      width: 240,
      color: {
        dark: "#2E3440",
        light: "#ECEFF4",
      },
    }).then((next) => {
      if (active) {
        setSvg(next);
      }
    });
    return () => {
      active = false;
    };
  }, [value]);

  return (
    <div className="preview-modal-backdrop" onClick={onClose}>
      <div className="preview-modal qr-modal" onClick={(event) => event.stopPropagation()}>
        <div className="card-header">
          <div>
            <h3>{title}</h3>
            <p className="muted">Scan or share this QR code to add the contact link.</p>
          </div>
          <button className="ghost-button compact-button" onClick={onClose}>Close</button>
        </div>
        <div className="qr-modal-body">
          <div className="qr-frame" dangerouslySetInnerHTML={{ __html: svg }} />
          <code className="qr-link">{value}</code>
        </div>
      </div>
    </div>
  );
}
