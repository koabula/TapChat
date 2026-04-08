import { fileNameFromPath } from "../../app/formatters";

export default function AttachmentDraftQueue({
  paths,
  onRemove,
}: {
  paths: string[];
  onRemove: (path: string) => void;
}) {
  return (
    <div className="attachment-draft-queue">
      {paths.map((path) => (
        <span className="status-chip inline attachment-draft-item" key={path}>
          {fileNameFromPath(path)}
          <button className="draft-remove-button" onClick={() => onRemove(path)}>x</button>
        </span>
      ))}
    </div>
  );
}
