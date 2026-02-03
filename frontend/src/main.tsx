import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import './styles/globals.css'
import './styles/layout.css'
import './styles/scan.css'
import './styles/dashboard.css'
import './styles/vulnerability.css'
import './styles/xai.css'
import './styles/report.css'
import './styles/info.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
