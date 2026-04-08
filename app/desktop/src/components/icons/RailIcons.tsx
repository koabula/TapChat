function iconProps() {
  return {
    width: 20,
    height: 20,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.8,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true,
    className: "rail-icon",
  };
}

export function ChatsIcon() {
  return (
    <svg {...iconProps()}>
      <path d="M4 6.5a2.5 2.5 0 0 1 2.5-2.5h11A2.5 2.5 0 0 1 20 6.5v7A2.5 2.5 0 0 1 17.5 16H10l-4.5 4v-4H6.5A2.5 2.5 0 0 1 4 13.5z" />
      <path d="M8 8h8M8 11h6" />
    </svg>
  );
}

export function ContactsIcon() {
  return (
    <svg {...iconProps()}>
      <path d="M15.5 19.5v-1a3.5 3.5 0 0 0-3.5-3.5h-4a3.5 3.5 0 0 0-3.5 3.5v1" />
      <circle cx="10" cy="8" r="3" />
      <path d="M18 9.5a2.5 2.5 0 0 1 0 5M19.5 19.5v-1a3 3 0 0 0-2-2.8" />
    </svg>
  );
}

export function RequestsIcon() {
  return (
    <svg {...iconProps()}>
      <path d="M4 7.5A2.5 2.5 0 0 1 6.5 5h11A2.5 2.5 0 0 1 20 7.5v9A2.5 2.5 0 0 1 17.5 19h-11A2.5 2.5 0 0 1 4 16.5z" />
      <path d="m6 8 6 5 6-5" />
    </svg>
  );
}

export function RuntimeIcon() {
  return (
    <svg {...iconProps()}>
      <path d="M7 18h10a4 4 0 0 0 0-8 5.5 5.5 0 0 0-10.5-1.5A4 4 0 0 0 7 18Z" />
    </svg>
  );
}

export function PolicyIcon() {
  return (
    <svg {...iconProps()}>
      <path d="M12 3l7 3v5c0 4.5-2.8 7.6-7 10-4.2-2.4-7-5.5-7-10V6z" />
      <path d="m9.5 11.5 1.7 1.7 3.3-3.7" />
    </svg>
  );
}

export function DiagnosticsIcon() {
  return (
    <svg {...iconProps()}>
      <path d="M4 12h3l2-5 4 10 2-5h5" />
    </svg>
  );
}

export function SunIcon() {
  return (
    <svg {...iconProps()}>
      <circle cx="12" cy="12" r="3.5" />
      <path d="M12 2.5v2M12 19.5v2M21.5 12h-2M4.5 12h-2M18.7 5.3l-1.4 1.4M8.7 15.3l-1.4 1.4M18.7 18.7l-1.4-1.4M8.7 8.7 7.3 7.3" />
    </svg>
  );
}

export function MoonIcon() {
  return (
    <svg {...iconProps()}>
      <path d="M20 14.2A7.5 7.5 0 0 1 9.8 4a8 8 0 1 0 10.1 10.2Z" />
    </svg>
  );
}
