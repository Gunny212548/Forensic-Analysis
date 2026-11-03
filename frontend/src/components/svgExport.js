// The attack path as pictures for the report draft (specs/forensic_report.md R-D9): the SVG
// the page draws, made to stand alone, and a PNG of it for Word versions that show no SVG.
//
// The page's SVG takes its colours from CSS (.ag-* rules over theme tokens), which a Word
// file does not carry, so every drawn element gets its computed style written onto it.
// The styles are read under the light theme whatever the analyst is using: the draft is a
// white page. Fonts are not embedded - Word and the canvas use the first one installed
// (IBM Plex if it is, else Segoe UI / Tahoma).

const PROPS = ['fill', 'fill-opacity', 'stroke', 'stroke-width', 'stroke-opacity', 'stroke-dasharray',
  'stroke-linecap', 'stroke-linejoin', 'opacity', 'font-family', 'font-size', 'font-weight',
  'letter-spacing', 'text-anchor', 'dominant-baseline']
const FONTS = '"IBM Plex Sans", "IBM Plex Sans Thai", "Segoe UI", Tahoma, sans-serif'
const MONO = '"IBM Plex Mono", Consolas, "Courier New", monospace'

function inline(src, dst) {
  const cs = window.getComputedStyle(src)
  for (const p of PROPS) {
    let v = cs.getPropertyValue(p)
    if (!v) continue
    if (p === 'font-family') v = /mono/i.test(v) ? MONO : FONTS
    dst.setAttribute(p, v)
  }
  dst.removeAttribute('class')
  for (let i = 0; i < src.children.length; i++) inline(src.children[i], dst.children[i])
}

/** A standalone copy of `svg` (an <svg> element in the page): {svg: Blob, png: Blob}. */
export async function exportSvg(svg, scale = 2) {
  const root = document.documentElement
  const theme = root.getAttribute('data-theme')
  root.setAttribute('data-theme', 'light')
  let text
  let width
  let height
  try {
    const copy = svg.cloneNode(true)
    inline(svg, copy)
    const box = svg.viewBox.baseVal
    width = Math.ceil(box?.width || svg.clientWidth)
    height = Math.ceil(box?.height || svg.clientHeight)
    copy.setAttribute('xmlns', 'http://www.w3.org/2000/svg')
    copy.setAttribute('width', width)
    copy.setAttribute('height', height)
    copy.removeAttribute('role')
    // A white page under it - the page's panel colour is not in the file.
    const bg = document.createElementNS('http://www.w3.org/2000/svg', 'rect')
    bg.setAttribute('width', '100%')
    bg.setAttribute('height', '100%')
    bg.setAttribute('fill', '#FFFFFF')
    copy.insertBefore(bg, copy.firstChild)
    // Tooltips (<title>) are the page's, not the picture's.
    copy.querySelectorAll('title').forEach((t) => t.remove())
    text = new XMLSerializer().serializeToString(copy)
  } finally {
    if (theme === null) root.removeAttribute('data-theme')
    else root.setAttribute('data-theme', theme)
  }
  const svgBlob = new Blob([text], { type: 'image/svg+xml' })
  const url = URL.createObjectURL(svgBlob)
  try {
    const img = await new Promise((resolve, reject) => {
      const i = new Image()
      i.onload = () => resolve(i)
      i.onerror = () => reject(new Error('The attack path could not be drawn as a picture'))
      i.src = url
    })
    const canvas = document.createElement('canvas')
    canvas.width = width * scale
    canvas.height = height * scale
    const ctx = canvas.getContext('2d')
    ctx.scale(scale, scale)
    ctx.drawImage(img, 0, 0, width, height)
    const png = await new Promise((resolve, reject) =>
      canvas.toBlob((b) => (b ? resolve(b) : reject(new Error('The attack path PNG could not be made'))), 'image/png'))
    return { svg: svgBlob, png }
  } finally {
    URL.revokeObjectURL(url)
  }
}
