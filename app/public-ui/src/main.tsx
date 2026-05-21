import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App";


createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>
);

// Fade out the HTML splash once React has mounted.
const splash = document.getElementById("splash");
if (splash) {
  splash.classList.add("fade-out");
  splash.addEventListener("transitionend", () => splash.remove(), { once: true });
}
