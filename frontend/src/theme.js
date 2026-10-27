/** Light or dark, chosen by the analyst with the button in the menu and kept
 *  in this browser only. Light is the default and the OS setting is not
 *  followed: the page never changes look unless the analyst asked it to. */

const KEY = 'fa_theme'

export function storedTheme() {
  try {
    return localStorage.getItem(KEY) === 'dark' ? 'dark' : 'light'
  } catch {
    return 'light' // storage blocked (private window, site data off)
  }
}

export function applyTheme(theme) {
  document.documentElement.dataset.theme = theme
}

export function saveTheme(theme) {
  applyTheme(theme)
  try {
    localStorage.setItem(KEY, theme)
  } catch {
    // Not remembered, but this page still switches.
  }
}
