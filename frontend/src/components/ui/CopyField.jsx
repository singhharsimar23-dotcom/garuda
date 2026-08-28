import React, { useState } from "react"
import { Copy, Check } from "lucide-react"

export default function CopyField({ value }) {
  const [copied, setCopied] = useState(false)

  function handleCopy() {
    if (!value) return
    navigator.clipboard.writeText(String(value)).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    })
  }

  return (
    <span className="inline-flex items-center gap-1.5 group max-w-full">
      <span className="font-data text-xs text-primary truncate">{value || "—"}</span>
      <button
        onClick={handleCopy}
        title="Copy to clipboard"
        className="shrink-0 text-ghost hover:text-secondary transition-colors duration-150"
      >
        {copied
          ? <Check className="w-3 h-3 text-low" />
          : <Copy className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity duration-150" />
        }
      </button>
    </span>
  )
}
