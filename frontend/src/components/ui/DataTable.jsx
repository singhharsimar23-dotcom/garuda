import React, { useState, useCallback, useRef, useEffect } from "react"
import { clsx } from "clsx"
import { ChevronUp, ChevronDown, ChevronsUpDown } from "lucide-react"

// ---------------------------------------------------------------------------
// Context Menu
// ---------------------------------------------------------------------------
function ContextMenu({ x, y, items, onClose }) {
  const ref = useRef(null)

  useEffect(() => {
    function handler(e) {
      if (ref.current && !ref.current.contains(e.target)) onClose()
    }
    document.addEventListener("mousedown", handler)
    return () => document.removeEventListener("mousedown", handler)
  }, [onClose])

  return (
    <div
      ref={ref}
      style={{ top: y, left: x, position: "fixed", zIndex: 9999 }}
      className="bg-surface border border-border shadow-lg py-1 min-w-[140px]"
    >
      {items.map((item) => (
        <button
          key={item.label}
          onClick={() => { item.action(); onClose() }}
          className="w-full text-left px-3 py-1.5 text-xs text-primary hover:bg-raised transition-colors duration-[80ms]"
        >
          {item.label}
        </button>
      ))}
    </div>
  )
}

// ---------------------------------------------------------------------------
// DataTable
// ---------------------------------------------------------------------------
/**
 * columns: Array<{
 *   key: string,
 *   label: string,
 *   mono?: boolean,       // use JetBrains Mono for this column
 *   sortable?: boolean,
 *   render?: (value, row) => ReactNode,
 *   width?: string,       // Tailwind width class e.g. 'w-32'
 * }>
 *
 * rows: Array<object>  — each row must have a unique `id` field
 *
 * contextMenuItems: (row) => Array<{ label, action }> | null
 */
export default function DataTable({
  columns = [],
  rows = [],
  onRowClick,
  sortable = true,
  selectable = false,
  contextMenuItems,
  emptyMessage = "No records",
  className,
}) {
  const [sortKey, setSortKey]   = useState(null)
  const [sortDir, setSortDir]   = useState("asc")
  const [selected, setSelected] = useState(new Set())
  const [ctxMenu, setCtxMenu]   = useState(null)

  // ---- Sorting ----
  function handleSort(key) {
    if (!sortable) return
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"))
    } else {
      setSortKey(key)
      setSortDir("asc")
    }
  }

  const sorted = React.useMemo(() => {
    if (!sortKey) return rows
    return [...rows].sort((a, b) => {
      const va = a[sortKey] ?? ""
      const vb = b[sortKey] ?? ""
      const cmp = String(va).localeCompare(String(vb), undefined, { numeric: true })
      return sortDir === "asc" ? cmp : -cmp
    })
  }, [rows, sortKey, sortDir])

  // ---- Selection ----
  function toggleSelect(id) {
    setSelected((prev) => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  // ---- Context menu ----
  function handleContextMenu(e, row) {
    if (!contextMenuItems) return
    const items = contextMenuItems(row)
    if (!items || items.length === 0) return
    e.preventDefault()
    setCtxMenu({ x: e.clientX, y: e.clientY, items, row })
  }

  function SortIcon({ colKey }) {
    if (sortKey !== colKey) return <ChevronsUpDown className="w-3 h-3 text-ghost" />
    return sortDir === "asc"
      ? <ChevronUp className="w-3 h-3 text-saffron" />
      : <ChevronDown className="w-3 h-3 text-saffron" />
  }

  return (
    <div className={clsx("relative overflow-x-auto border border-border", className)}>
      <table className="w-full border-collapse">
        {/* Header */}
        <thead>
          <tr className="bg-surface">
            {selectable && (
              <th className="w-8 px-3 py-2 text-left">
                <input
                  type="checkbox"
                  className="accent-saffron"
                  checked={selected.size === rows.length && rows.length > 0}
                  onChange={() =>
                    setSelected(
                      selected.size === rows.length
                        ? new Set()
                        : new Set(rows.map((r) => r.id))
                    )
                  }
                />
              </th>
            )}
            {columns.map((col) => (
              <th
                key={col.key}
                onClick={() => col.sortable !== false && handleSort(col.key)}
                className={clsx(
                  "px-3 py-2 text-left text-2xs font-semibold text-secondary uppercase tracking-widest whitespace-nowrap",
                  col.sortable !== false && sortable && "cursor-pointer hover:text-primary transition-colors duration-[80ms]",
                  col.width
                )}
              >
                <span className="inline-flex items-center gap-1">
                  {col.label}
                  {col.sortable !== false && sortable && <SortIcon colKey={col.key} />}
                </span>
              </th>
            ))}
          </tr>
        </thead>

        {/* Body */}
        <tbody>
          {sorted.length === 0 ? (
            <tr>
              <td
                colSpan={columns.length + (selectable ? 1 : 0)}
                className="px-3 py-10 text-center text-xs text-ghost"
              >
                {emptyMessage}
              </td>
            </tr>
          ) : (
            sorted.map((row, idx) => {
              const isSelected = selected.has(row.id)
              return (
                <tr
                  key={row.id ?? idx}
                  onClick={() => {
                    if (selectable) toggleSelect(row.id)
                    if (onRowClick) onRowClick(row)
                  }}
                  onContextMenu={(e) => handleContextMenu(e, row)}
                  className={clsx(
                    "border-0 transition-colors duration-[80ms]",
                    isSelected
                      ? "bg-rowsel"
                      : idx % 2 === 0
                        ? "bg-row hover:bg-raised"
                        : "bg-rowalt hover:bg-raised",
                    (onRowClick || selectable) && "cursor-pointer"
                  )}
                >
                  {selectable && (
                    <td className="px-3 py-2">
                      <input
                        type="checkbox"
                        className="accent-saffron"
                        checked={isSelected}
                        onChange={() => toggleSelect(row.id)}
                        onClick={(e) => e.stopPropagation()}
                      />
                    </td>
                  )}
                  {columns.map((col) => {
                    const val = row[col.key]
                    const content = col.render ? col.render(val, row) : (val ?? "—")
                    return (
                      <td
                        key={col.key}
                        className={clsx(
                          "px-3 py-2 text-sm text-primary whitespace-nowrap max-w-xs truncate",
                          col.mono && "font-data"
                        )}
                      >
                        {content}
                      </td>
                    )
                  })}
                </tr>
              )
            })
          )}
        </tbody>
      </table>

      {/* Context Menu */}
      {ctxMenu && (
        <ContextMenu
          x={ctxMenu.x}
          y={ctxMenu.y}
          items={ctxMenu.items}
          onClose={() => setCtxMenu(null)}
        />
      )}
    </div>
  )
}
