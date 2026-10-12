import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import TopBar from './TopBar'

/**
 * Layout — wraps every page with the sidebar + topbar shell.
 * Page content is rendered via <Outlet />.
 */
export default function Layout() {
  return (
    <div className="flex h-screen overflow-hidden bg-surface-900">
      {/* ── Sidebar ── */}
      <Sidebar />

      {/* ── Main content area ── */}
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-6 lg:p-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
