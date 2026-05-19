import { Link } from "react-router-dom";

export default function NotFoundPage() {
  return (
    <div className="text-center py-20">
      <h1 className="text-3xl font-semibold mb-2">404</h1>
      <p className="text-slate-500 dark:text-slate-400 mb-6">
        The page you're looking for doesn't exist.
      </p>
      <Link to="/" className="text-blue-600 dark:text-blue-400 hover:underline">
        Back to projects
      </Link>
    </div>
  );
}
