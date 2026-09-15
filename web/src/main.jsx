import React from "react";
import { createRoot } from "react-dom/client";
import CardanoKeyExplorer from "./CardanoKeyExplorer.jsx";

document.body.style.margin = "0";
document.body.style.background = "#0b1119";
document.body.style.minHeight = "100vh";

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <CardanoKeyExplorer />
  </React.StrictMode>
);
