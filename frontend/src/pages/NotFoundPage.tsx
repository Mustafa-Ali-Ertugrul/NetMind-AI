import { Link } from 'react-router-dom';

export function NotFoundPage() {
  return (
    <div className="text-center py-16">
      <h2 className="text-2xl font-bold text-gray-900 mb-2">404 — Page not found</h2>
      <p className="text-sm text-gray-500 mb-4">The page you are looking for does not exist.</p>
      <Link to="/upload" className="text-sm text-blue-600 hover:underline">
        Go to Upload
      </Link>
    </div>
  );
}
