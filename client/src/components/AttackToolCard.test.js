import { createRoot } from 'react-dom/client';
import { act } from 'react-dom/test-utils';
import AttackToolCard from './AttackToolCard';
import { ATTACK_TOOL_SECTIONS } from '../data/attackTools';

beforeAll(() => { global.IS_REACT_ACT_ENVIRONMENT = true; });

test('every tool renders a card with the three buttons', async () => {
  const clicks = [];
  for (const section of ATTACK_TOOL_SECTIONS) {
    console.log(`\n${section.title}  (${section.tools.length})  ${section.blurb}`);
    for (const tool of section.tools) {
      document.body.innerHTML = '';
      const c = document.createElement('div');
      document.body.appendChild(c);
      const root = createRoot(c);
      await act(async () => {
        root.render(<AttackToolCard tool={tool}
          onConfig={(t) => clicks.push(['Config', t.name])}
          onScan={(t) => clicks.push(['Scan', t.name])}
          onResults={(t) => clicks.push(['Results', t.name])} />);
      });
      const buttons = [...document.body.querySelectorAll('button')].map((b) => b.textContent.trim());
      ['Config', 'Scan', 'Results'].forEach((b) => expect(buttons).toContain(b));
      console.log(`   ${tool.name.padEnd(32)} ${tool.description.slice(0, 62)}`);
      // The card matches every other tool card in the workflow: a linked name, one italic line, and
      // the three buttons. Nothing else, so these sections do not read differently from the ones
      // above them.
      expect(buttons).toHaveLength(3);
      expect(document.body.querySelectorAll('.badge')).toHaveLength(0);
      expect(document.body.querySelectorAll('pre')).toHaveLength(0);
      expect(document.body.querySelector('a').textContent.trim()).toBe(tool.name);
      // And the buttons call back with the tool.
      ['Config', 'Scan', 'Results'].forEach((label) => {
        [...document.body.querySelectorAll('button')]
          .find((b) => b.textContent.trim() === label).click();
      });
    }
  }
  // Counted from the data rather than written down, so adding a tool cannot make this stale.
  const toolCount = ATTACK_TOOL_SECTIONS.reduce((n, s) => n + s.tools.length, 0);
  expect(clicks).toHaveLength(toolCount * 3);
  expect(clicks.filter(([a]) => a === 'Scan')).toHaveLength(toolCount);
  // Keys have to be unique or React reuses a card for a different tool.
  const keys = ATTACK_TOOL_SECTIONS.flatMap((s) => s.tools.map((t) => `${s.key}/${t.key}`));
  expect(new Set(keys).size).toBe(keys.length);
  expect(new Set(ATTACK_TOOL_SECTIONS.map((s) => s.key)).size)
    .toBe(ATTACK_TOOL_SECTIONS.length);
});
