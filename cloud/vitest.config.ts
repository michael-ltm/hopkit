import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
export default defineConfig({plugins:[cloudflareTest({miniflare:{compatibilityDate:'2026-08-22'},wrangler:{configPath:'./wrangler.jsonc'}})],test:{testTimeout:30000}});
