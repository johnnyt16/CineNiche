import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import logoImage from '../cineniche-high-resolution2.png';
import { moviesApi, MovieTitle } from '../services/api';

// Sample movie images for carousel (fallback)
const fallbackMovieImages = [
  { id: 1, src: "https://m.media-amazon.com/images/M/MV5BNzQzOTk3OTAtNDQ0Zi00ZTVkLWI0MTEtMDllZjNkYzNjNTc4L2ltYWdlXkEyXkFqcGdeQXVyNjU0OTQ0OTY@._V1_.jpg", title: "The Matrix" },
  { id: 2, src: "https://m.media-amazon.com/images/M/MV5BMDdmZGU3NDQtY2E5My00ZTliLWIzOTUtMTY4ZGI1YjdiNjk3XkEyXkFqcGdeQXVyNTA4NzY1MzY@._V1_.jpg", title: "Titanic" },
  { id: 3, src: "https://m.media-amazon.com/images/M/MV5BNzA5ZDNlZWMtM2NhNS00NDJjLTk4NDItYTRmY2EwMWZlMTY3XkEyXkFqcGdeQXVyNzkwMjQ5NzM@._V1_.jpg", title: "The Lord of the Rings" },
  { id: 4, src: "https://m.media-amazon.com/images/M/MV5BMTMxNTMwODM0NF5BMl5BanBnXkFtZTcwODAyMTk2Mw@@._V1_.jpg", title: "The Dark Knight" },
  { id: 6, src: "https://m.media-amazon.com/images/M/MV5BNWIwODRlZTUtY2U3ZS00Yzg1LWJhNzYtMmZiYmEyNmU1NjMzXkEyXkFqcGdeQXVyMTQxNzMzNDI@._V1_.jpg", title: "Forrest Gump" },
  { id: 8, src: "https://m.media-amazon.com/images/M/MV5BZjdkOTU3MDktN2IxOS00OGEyLWFmMjktY2FiMmZkNWIyODZiXkEyXkFqcGdeQXVyMTMxODk2OTU@._V1_.jpg", title: "Interstellar" }
];

// Sample recommended movies (fallback)
const fallbackRecommendedMovies = [
  { id: 10, src: "https://m.media-amazon.com/images/M/MV5BNWM1NmYyM2ItMTFhNy00NDU0LTk2ODItYWEyMzQ5MThmNzVhXkEyXkFqcGdeQXVyNTU1OTUzNDg@._V1_.jpg", title: "Eraserhead" },
  { id: 11, src: "https://m.media-amazon.com/images/M/MV5BNDg4NjM1YjMtYmNhZC00MjM0LWFiZmYtNGY1YjA3MzZmODc5XkEyXkFqcGdeQXVyNDk3NzU2MTQ@._V1_.jpg", title: "Brazil" },
  { id: 12, src: "https://m.media-amazon.com/images/M/MV5BNWZiMTFiZTgtN2I1OC00MDgxLWI2ZmQtNDFiYmQ5MzlhZDZlXkEyXkFqcGdeQXVyMTMxODk2OTU@._V1_.jpg", title: "Stalker" },
  { id: 13, src: "https://m.media-amazon.com/images/M/MV5BYzQzNTU3OTAtZmY4NS00NzJmLTg2M2UtMmQwNWY0MWRhOWZkXkEyXkFqcGdeQXVyMTY5Nzc4MDY@._V1_.jpg", title: "Holy Mountain" },
  { id: 14, src: "https://m.media-amazon.com/images/M/MV5BMjFkMTYwOGItMTBiYS00YjZiLWJkNGMtNjliZThjMWI0NWY3XkEyXkFqcGdeQXVyMTkxNjUyNQ@@._V1_.jpg", title: "Mandy" },
  { id: 15, src: "https://m.media-amazon.com/images/M/MV5BMDE3ZmY0OGQtNWI4MS00OWI1LWJjOTUtZGIzYTJjNzkzYzM2XkEyXkFqcGdeQXVyODk4OTc3MTY@._V1_.jpg", title: "Everything Everywhere All at Once" }
];

// Convert MovieTitle to carousel item format
const convertToCarouselItem = (movie: MovieTitle) => {
  return {
    id: movie.show_id,
    src: `https://via.placeholder.com/300x450?text=${encodeURIComponent(movie.title || 'Movie')}`,
    title: movie.title || 'Untitled'
  };
};

const HomePage: React.FC = () => {
    const { isAuthenticated, user } = useAuth();
    const carouselRef = useRef<HTMLDivElement>(null);
    const recommendedCarouselRef = useRef<HTMLDivElement>(null);
    const [movieImages, setMovieImages] = useState<Movie[]>([]);
    const [recommendedMovies, setRecommendedMovies] = useState<Movie[]>([]);
    const [isPaused, setIsPaused] = useState(false);
    const [isRecommendedPaused, setIsRecommendedPaused] = useState(false);

    useEffect(() => {
        const fetchMovies = async () => {
            try {
                const response = await moviesApi.getMoviesPaged(1, 10);
                const movies = await Promise.all(response.movies.map(convertToMovie));
                setMovieImages([...movies, ...movies]);
            } catch (err) {
                console.error('Failed to fetch recent movies:', err);
            }
        };

        const fetchRecommendations = async () => {
            if (!user?.id) return;
            try {
                const recs = await moviesApi.getCollaborativeRecommendations(user.id);
                const recommended = await Promise.all(recs.map(convertToMovie));
                setRecommendedMovies([...recommended, ...recommended]);
            } catch (err) {
                console.error('Failed to fetch recommended movies:', err);
            }
        };

        fetchMovies();
        fetchRecommendations();
    }, [user]);

    const useInfiniteScroll = (ref: React.RefObject<HTMLDivElement>, paused: boolean) => {
        useEffect(() => {
            let animationFrameId: number;
            const scrollSpeed = 0.5;

            const scroll = () => {
                if (ref.current && !paused) {
                    ref.current.scrollLeft += scrollSpeed;
                    if (ref.current.scrollLeft >= ref.current.scrollWidth / 2) {
                        ref.current.scrollLeft = 0;
                    }
                }
                animationFrameId = requestAnimationFrame(scroll);
            };

            animationFrameId = requestAnimationFrame(scroll);
            return () => cancelAnimationFrame(animationFrameId);
        }, [ref, paused]);
    };

    useInfiniteScroll(carouselRef, isPaused);
    useInfiniteScroll(recommendedCarouselRef, isRecommendedPaused);

    return (
        <div className="home-page">
            <div className="full-width-hero">
                <div className="hero-overlay">
                    <div className="hero-content">
                        {isAuthenticated ? (
                            <h1>Welcome, {user?.name.split(' ')[0]}</h1>
                        ) : (
                            <div className="welcome-container">
                                <h1>Welcome to</h1>
                                <img src={logoImage} alt="CineNiche" className="welcome-logo" />
                            </div>
                        )}
                        <p>Discover the world's most intriguing cult classics and rare films</p>
                        <Link to="/movies" className="btn-explore">Explore Collection</Link>
                    </div>
                </div>
            </div>

            {isAuthenticated && recommendedMovies.length > 0 && (
                <div className="featured-films-section recommended-section">
                    <div className="section-header container">
                        <h2>Recommended For You</h2>
                    </div>
                    <div
                        className="film-scroll-container overflow-hidden"
                        ref={recommendedCarouselRef}
                        onMouseEnter={() => setIsRecommendedPaused(true)}
                        onMouseLeave={() => setIsRecommendedPaused(false)}
                    >
                        <div className="film-scroll-track flex gap-4 w-max">
                            {[...recommendedMovies, ...recommendedMovies].map((movie, idx) => (
                                <Link to={`/movies/${movie.id}`} key={`rec-${movie.id}-${idx}`} className="film-item flex-none w-48">
                                    <img src={movie.poster} alt={movie.title} />
                                    <p>{movie.title}</p>
                                </Link>
                            ))}
                        </div>
                    </div>
                </div>
            )}

            <div className="featured-films-section">
                <div className="section-header container">
                    <h2>Recently Added</h2>
                </div>
                <div
                    className="film-scroll-container overflow-hidden"
                    ref={carouselRef}
                    onMouseEnter={() => setIsPaused(true)}
                    onMouseLeave={() => setIsPaused(false)}
                >
                    <div className="film-scroll-track flex gap-4 w-max">
                        {[...movieImages, ...movieImages].map((movie, idx) => (
                            <Link to={`/movies/${movie.id}`} key={`recent-${movie.id}-${idx}`} className="film-item flex-none w-48">
                                <img src={movie.poster} alt={movie.title} />
                                <p>{movie.title}</p>
                            </Link>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default HomePage; 