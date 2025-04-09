import React from 'react';
import { Routes, Route } from 'react-router-dom';

// Import pages
import HomePage from './pages/HomePage';
import MoviesPage from './pages/MoviesPage';
import MovieDetailPage from './pages/MovieDetailPage';
import AddMoviePage from './pages/AddMoviePage';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import PrivacyPage from './pages/PrivacyPage';
import TermsPage from './pages/TermsPage';
import MyReviewsPage from './pages/MyReviewsPage';
import ProfilePage from './pages/ProfilePage';
import WatchPage from './pages/WatchPage';
import PosterDebugPage from './pages/PosterDebugPage';
import RegisterProfilePage from './pages/RegisterProfilePage';

// Import components
import Navbar from './components/Navbar';
import Footer from './components/Footer';

// Import auth provider
import { AuthProvider } from './context/AuthContext';

const App: React.FC = () => {
  return (
    <AuthProvider>
      <div className="app">
        <Navbar />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/movies" element={<MoviesPage />} />
            <Route path="/movies/add" element={<AddMoviePage />} />
            <Route path="/movies/:id" element={<MovieDetailPage />} />
            <Route path="/watch/:id" element={<WatchPage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route path="/privacy" element={<PrivacyPage />} />
            <Route path="/terms" element={<TermsPage />} />
            <Route path="/my-reviews" element={<MyReviewsPage />} />
            <Route path="/profile" element={<ProfilePage />} />
            <Route path="/debug/posters" element={<PosterDebugPage />} />
            <Route path="/register-profile" element={<RegisterProfilePage />} />
          </Routes>
        </main>
        <Footer />
      </div>
    </AuthProvider>
  );
};

export default App;
