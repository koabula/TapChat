import { useNavigate } from "react-router";

export default function Welcome() {
  const navigate = useNavigate();

  return (
    <div className="flex flex-col items-center justify-center h-screen bg-base p-8">
      {/* Logo placeholder */}
      <div className="w-16 h-16 rounded-full bg-primary mb-6 flex items-center justify-center">
        <span className="text-2xl font-bold text-white">T</span>
      </div>

      <h1 className="text-3xl font-semibold text-primary-color mb-2">
        TapChat
      </h1>
      <p className="text-secondary-color text-center mb-8">
        Private. Decentralized.<br />
        Yours.
      </p>

      <div className="flex flex-col gap-4 w-full max-w-xs">
        <button
          className="btn btn-primary w-full"
          onClick={() => navigate("/onboarding/identity")}
        >
          Create New Identity
        </button>
        <button
          className="btn btn-secondary w-full"
          onClick={() => navigate("/onboarding/identity?mode=recover")}
        >
          Recover Existing Identity
        </button>
      </div>
    </div>
  );
}