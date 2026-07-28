import aegisPreset from "@aegis/ui/preset";
import type { Config } from "tailwindcss";
import animate from "tailwindcss-animate";

export default {
  presets: [aegisPreset],
  content: ["./src/**/*.{ts,tsx}"],
  plugins: [animate],
} satisfies Config;
