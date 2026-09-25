import { Languages } from 'lucide-react'

export default function LanguageNotice({ value }) {
  if (!value || value.model_coverage === 'supported') return null
  return <section className="ps-section language-notice" role="note" aria-label="Language coverage">
    <h2><Languages size={16} aria-hidden="true"/> Language coverage</h2>
    <p><strong>{value.language}</strong> - {value.script}</p>
    <p className="caveat">{value.note}</p>
  </section>
}
