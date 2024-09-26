import type { LoadConfig } from "./types";

const defaultLoadConfig: Required<LoadConfig> = {
  pluginBaseURL: "https://cdn.live.ledger.com",
  extraPlugins: null,
  cryptoassetsBaseURL: "https://cdn.live.ledger.com/cryptoassets",
  calServiceURL: "https://crypto-assets-service.api.ledger.com",
};

export function getLoadConfig(userLoadConfig?: LoadConfig): LoadConfig {
  return {
    ...defaultLoadConfig,
    ...userLoadConfig,
  };
}
