import { defineConfig, transformWithOxc } from 'vite';
import react from '@vitejs/plugin-react';

// Create React App compiled JSX inside .js files, and most of src/ relies on that. Vite only does it
// for .jsx, so this plugin compiles JSX in our own src/**/*.js. node_modules keep Vite's defaults.
// (Vite 8 ignores `oxc.lang` and a load hook's moduleType for this, so a transform is the way.)
const SRC_JS = /[\\/]src[\\/].*\.js$/;
const jsxInJs = {
  name: 'ars0n:jsx-in-js',
  enforce: 'pre',
  async transform(code, id) {
    const file = id.split('?')[0];
    if (!SRC_JS.test(file) || file.includes('node_modules')) return null;
    const r = await transformWithOxc(code, file, { lang: 'jsx', jsx: { runtime: 'automatic' }, sourcemap: true });
    return { code: r.code, map: r.map, moduleType: 'js' };
  },
};

export default defineConfig({
  plugins: [jsxInJs, react()],
  // The dependency pre-bundler scans src/ too, so it must also read .js as JSX.
  optimizeDeps: { rolldownOptions: { moduleTypes: { '.js': 'jsx' } } },
  // build/ is where CRA wrote, and where the Dockerfile copies from. No source maps are published.
  build: { outDir: 'build', sourcemap: false },
  server: { port: 3000 },
  test: {
    environment: 'jsdom',
    // The tests use describe/test/expect without importing them, as they did under Jest.
    globals: true,
    // CRA set Jest's resetMocks: mocks are reset before every test.
    mockReset: true,
    setupFiles: ['./src/setupTests.js'],
    include: ['src/**/*.{test,spec}.js'],
    css: false,
  },
});
