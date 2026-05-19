import { Route, Routes, NavLink, Link } from "react-router-dom";
import ProjectsPage from "./pages/ProjectsPage";
import ProjectDetailPage from "./pages/ProjectDetailPage";
import NewProjectPage from "./pages/NewProjectPage";
import RunDetailPage from "./pages/RunDetailPage";
import NotFoundPage from "./pages/NotFoundPage";

export default function App() {
  return (
    <div className="min-h-full flex flex-col">
      <Header />
      <main className="flex-1 max-w-6xl w-full mx-auto px-4 py-6">
        <Routes>
          <Route path="/" element={<ProjectsPage />} />
          <Route path="/projects/new" element={<NewProjectPage />} />
          <Route path="/projects/:projectID" element={<ProjectDetailPage />} />
          <Route
            path="/projects/:projectID/runs/:runID"
            element={<RunDetailPage />}
          />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </main>
      <footer className="text-xs text-slate-500 dark:text-slate-400 text-center py-4 border-t border-slate-200 dark:border-slate-800">
        GoLantern — LCVA workflow engine
      </footer>
    </div>
  );
}

function Header() {
  return (
    <header className="border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
      <div className="max-w-6xl mx-auto px-4 py-3 flex items-center gap-6">
        <Link to="/" className="font-semibold text-lg">
          GoLantern
        </Link>
        <nav className="flex gap-4 text-sm">
          <NavLink
            to="/"
            end
            className={({ isActive }) =>
              isActive
                ? "text-blue-600 dark:text-blue-400 font-medium"
                : "text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white"
            }
          >
            Projects
          </NavLink>
          <NavLink
            to="/projects/new"
            className={({ isActive }) =>
              isActive
                ? "text-blue-600 dark:text-blue-400 font-medium"
                : "text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white"
            }
          >
            New project
          </NavLink>
        </nav>
      </div>
    </header>
  );
}
