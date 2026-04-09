import { createSignal } from "solid-js";
import type { Component } from "solid-js";

const TOKEN_KEY = "streamtrace_token";

function loadToken(): string {
  try {
    return localStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

const Header: Component = () => {
  const [token, setToken] = createSignal(loadToken());

  function saveToken(): void {
    try {
      const value = token().trim();
      if (value) {
        localStorage.setItem(TOKEN_KEY, value);
      } else {
        localStorage.removeItem(TOKEN_KEY);
      }
    } catch {
      // localStorage may be unavailable
    }
  }

  return (
    <header class="header">
      <span class="header__title">StreamTrace</span>
      <div class="header__token-group">
        <input
          type="password"
          class="header__token-input"
          placeholder="Bearer token"
          value={token()}
          onInput={(e) => setToken(e.currentTarget.value)}
          aria-label="API bearer token"
        />
        <button class="header__token-btn" onClick={saveToken} type="button">
          Save
        </button>
      </div>
    </header>
  );
};

export default Header;
