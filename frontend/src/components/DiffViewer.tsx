/** Renders a unified diff produced by the ASE backend. Added/removed/context lines are visually and textually distinct. */
export default function DiffViewer({ diff }: { diff: string }) {
  const lines = diff.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  return <div className="overflow-x-auto rounded border border-slate-700 bg-slate-950 font-mono text-xs" aria-label="Proposed patch diff">
    {lines.map((line, i) => {
      const header = line.startsWith('---') || line.startsWith('+++');
      const kind = header ? 'meta' : line.startsWith('@@') ? 'hunk' : line.startsWith('+') ? 'add' : line.startsWith('-') ? 'del' : 'ctx';
      const style = { meta: 'text-slate-400', hunk: 'text-cyan-300 bg-slate-900', add: 'bg-green-950/70 text-green-200', del: 'bg-red-950/70 text-red-200', ctx: 'text-slate-300' }[kind];
      const label = { meta: 'file', hunk: 'hunk', add: 'added', del: 'removed', ctx: 'unchanged' }[kind];
      return <div key={i} className={'px-3 py-0.5 whitespace-pre ' + style} data-diff-kind={kind}>
        <span className="sr-only">{label}: </span>{line || ' '}
      </div>;
    })}
  </div>;
}
