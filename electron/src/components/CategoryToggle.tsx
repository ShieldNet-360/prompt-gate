import type { CategoryPolicy, PolicyAction } from '../api/agent';

interface Props {
  policy: CategoryPolicy;
  disabled?: boolean;
  onChange: (action: PolicyAction) => void;
}

// Three-state segmented control: Allow / Allow + Inspect / Block.
// The agent's PUT /api/policies/:category endpoint accepts all three
// action values (`allow`, `allow_with_dlp`, `deny`) so the UI is
// purely a presentation layer over `policy.action`.
const OPTIONS: Array<{ action: PolicyAction; label: string; hint: string }> = [
  { action: 'allow', label: 'Allow', hint: 'Permit traffic without inspection.' },
  {
    action: 'allow_with_dlp',
    label: 'Allow + Inspect',
    hint: 'Permit traffic, but scan pastes / submissions through the DLP pipeline.',
  },
  { action: 'deny', label: 'Block', hint: 'Resolve DNS queries in this category to 0.0.0.0.' },
];

export function CategoryToggle({ policy, disabled, onChange }: Props) {
  return (
    <div
      className="category-row"
      role="radiogroup"
      aria-label={`Action for category ${policy.category}`}
    >
      <div className="category-name">{policy.category}</div>
      <div className="category-controls" role="group">
        {OPTIONS.map((opt) => {
          const selected = policy.action === opt.action;
          return (
            <button
              key={opt.action}
              type="button"
              role="radio"
              aria-checked={selected}
              title={opt.hint}
              disabled={disabled || selected}
              data-selected={selected}
              onClick={() => onChange(opt.action)}
            >
              {opt.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}
