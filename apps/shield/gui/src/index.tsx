import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";
import { Toaster } from "react-hot-toast";

const entryIndicator = document.createElement('div');
entryIndicator.id = 'ENTRY_OK';
entryIndicator.style.cssText = 'position:fixed;top:50px;left:0;background:blue;color:white;z-index:9999;padding:10px;';
entryIndicator.innerText = 'INDEX_JS_EXECUTING';
document.body.appendChild(entryIndicator);

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
    <Toaster
      position="bottom-right"
      toastOptions={{
        style: {
          background: "hsl(var(--card))",
          color: "hsl(var(--foreground))",
          border: "1px solid hsl(var(--border))",
          boxShadow: "var(--card-shadow)",
        },
      }}
    />
  </React.StrictMode>
);
