import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.jsx'
// The Figma's type, bundled rather than fetched, so an air-gapped case still
// renders in it (nothing is fetched at runtime - see CLAUDE.md). Plex Sans has
// no Thai glyphs; Plex Sans Thai is the same family's Thai cut.
import '@fontsource/ibm-plex-sans/400.css'
import '@fontsource/ibm-plex-sans/500.css'
import '@fontsource/ibm-plex-sans/600.css'
import '@fontsource/ibm-plex-sans/700.css'
import '@fontsource/ibm-plex-sans-thai/400.css'
import '@fontsource/ibm-plex-sans-thai/600.css'
import '@fontsource/ibm-plex-mono/400.css'
import '@fontsource/ibm-plex-mono/700.css'
import './styles.css'
import { applyTheme, storedTheme } from './theme.js'

// Before the first render, so a dark page does not flash light.
applyTheme(storedTheme())

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
