export default function Banner({ tone, message }: { tone: "error" | "success"; message: string }) {
  return <div className={tone === "error" ? "banner error" : "banner success"}>{message}</div>;
}
