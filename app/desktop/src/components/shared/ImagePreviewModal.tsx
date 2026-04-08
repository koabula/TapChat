export default function ImagePreviewModal({
  title,
  src,
  onClose,
}: {
  title: string;
  src: string;
  onClose: () => void;
}) {
  return (
    <div className="preview-modal-backdrop" onClick={onClose}>
      <div className="preview-modal" onClick={(event) => event.stopPropagation()}>
        <div className="card-header">
          <div>
            <span className="eyebrow">Image preview</span>
            <h3>{title}</h3>
          </div>
          <button className="ghost-button compact-button" onClick={onClose}>Close</button>
        </div>
        <img className="preview-modal-image" src={src} alt={title} />
      </div>
    </div>
  );
}
