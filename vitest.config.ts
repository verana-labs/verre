import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    coverage: {
      provider: "v8",
      reportsDirectory: "./coverage",
      exclude: ["build", "node_modules", "__tests__", "tests"],
    },
    include: ["**/?(*.)+(spec|test).[tj]s?(x)"],
    root: "./",
  },
});
