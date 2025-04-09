using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using CineNiche.API.Data;
using CineNiche.API.DTOs;

namespace CineNiche.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class MoviesController : ControllerBase
    {
        private readonly MoviesDbContext _context;
        private readonly RecommendationService _recommendationService;

        // Only keep ONE constructor that takes both dependencies
        public MoviesController(
            MoviesDbContext context,
            RecommendationService recommendationService)
        {
            _context = context;
            _recommendationService = recommendationService;
        }

        [HttpGet("titles")]
        public async Task<ActionResult<List<MovieTitleDto>>> GetMovieTitles()
        {
            var movies = await _context.Movies  
                .OrderBy(m => m.title ?? string.Empty)
                .ToListAsync();
            
            var movieDtos = movies.Select(m => MovieTitleDto.FromEntity(m)).ToList();
            return Ok(movieDtos);
        }

        [HttpGet("titles/paged")]
        public async Task<ActionResult<object>> GetMovieTitlesPaged([FromQuery] int page = 1, [FromQuery] int pageSize = 20)
        {
            if (page < 1) page = 1;
            if (pageSize < 1 || pageSize > 100) pageSize = 20;
            
            var totalCount = await _context.Movies.CountAsync();
            var totalPages = (int)Math.Ceiling(totalCount / (double)pageSize);
            
            var movies = await _context.Movies
                .OrderBy(m => m.title ?? string.Empty)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();
            
            var movieDtos = movies.Select(m => MovieTitleDto.FromEntity(m)).ToList();
            
            return Ok(new {
                movies = movieDtos,
                pagination = new {
                    currentPage = page,
                    pageSize = pageSize,
                    totalPages = totalPages,
                    totalCount = totalCount,
                    hasNext = page < totalPages,
                    hasPrevious = page > 1
                }
            });
        }

        [HttpGet("titles/{id}")]
        public async Task<ActionResult<MovieTitleDto>> GetMovieTitle(string id)
        {
            var movie = await _context.Movies.FindAsync(id);
            if (movie == null) return NotFound();
            
            return Ok(MovieTitleDto.FromEntity(movie));
        }

        [HttpGet("titles/{id}/recommendations")]
        public async Task<ActionResult<List<MovieTitleDto>>> GetMovieRecommendations(string id, [FromQuery] int? userId)
        {
            var recommendations = await _recommendationService.GetHybridRecommendations(id, userId);
            var dtos = recommendations.Select(m => MovieTitleDto.FromEntity(m)).ToList();
            return Ok(dtos);
        }

        [HttpGet("users")]
        public async Task<ActionResult<List<MovieUserDto>>> GetUsers()
        {
            var users = await _context.Users
                .OrderBy(u => u.name ?? string.Empty)
                .ToListAsync();
            
            var userDtos = users.Select(u => new MovieUserDto
            {
                Id = u.user_id,
                Name = u.name,
                Email = u.email,
                Phone = u.phone,
                Age = u.age,
                Gender = u.gender,
                City = u.city,
                State = u.state,
                IsAdmin = u.isAdmin == 1
            }).ToList();
            
            return Ok(userDtos);
        }

        [HttpGet("users/{id}")]
        public async Task<ActionResult<MovieUserDto>> GetUser(int id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null) return NotFound();
            
            var userDto = new MovieUserDto
            {
                Id = user.user_id,
                Name = user.name,
                Email = user.email,
                Phone = user.phone,
                Age = user.age,
                Gender = user.gender,
                City = user.city,
                State = user.state,
                IsAdmin = user.isAdmin == 1
            };
            
            return Ok(userDto);
        }
        
        [HttpGet("ratings/{showId}")]
        public async Task<ActionResult<List<MovieRatingDto>>> GetRatingsForMovie(string showId)
        {
            var ratings = await _context.Ratings
                .Where(r => r.show_id == showId)
                .Select(r => new MovieRatingDto
                {
                    user_id = r.user_id,
                    show_id = r.show_id,
                    rating = r.rating ?? 0
                })
                .ToListAsync();
                
            return Ok(ratings);
        }
        
        [HttpGet("ratings/user/{userId}")]
        public async Task<ActionResult<List<MovieRatingDto>>> GetUserRatings(int userId)
        {
            var ratings = await _context.Ratings
                .Where(r => r.user_id == userId)
                .Select(r => new MovieRatingDto
                {
                    user_id = r.user_id,
                    show_id = r.show_id,
                    rating = r.rating ?? 0
                })
                .ToListAsync();
                
            return Ok(ratings);
        }
        
        [HttpGet("ratings/average/{showId}")]
        public async Task<ActionResult<double>> GetAverageRating(string showId)
        {
            var ratings = await _context.Ratings
                .Where(r => r.show_id == showId && r.rating.HasValue)
                .Select(r => r.rating!.Value)
                .ToListAsync();
                
            if (!ratings.Any())
            {
                return Ok(0.0);
            }
            
            return Ok(ratings.Average());
        }
        
        // Favorites endpoints
        [HttpGet("favorites/user/{userId}")]
        public async Task<ActionResult<List<UserFavoriteDto>>> GetUserFavorites(int userId)
        {
            var favorites = await _context.Favorites
                .Where(f => f.user_id == userId)
                .Select(f => UserFavoriteDto.FromEntity(f))
                .ToListAsync();
                
            return Ok(favorites);
        }
        
        [HttpPost("favorites")]
        public async Task<ActionResult<UserFavoriteDto>> AddFavorite(UserFavoriteDto favoriteDto)
        {
            // Check if this favorite already exists
            var existingFavorite = await _context.Favorites
                .FirstOrDefaultAsync(f => f.user_id == favoriteDto.user_id && f.movie_id == favoriteDto.movie_id);
                
            if (existingFavorite != null)
            {
                return Ok(UserFavoriteDto.FromEntity(existingFavorite)); // Already exists
            }
            
            // Create new favorite
            var favorite = new UserFavorite
            {
                user_id = favoriteDto.user_id,
                movie_id = favoriteDto.movie_id
            };
            
            _context.Favorites.Add(favorite);
            await _context.SaveChangesAsync();
            
            return CreatedAtAction(nameof(GetUserFavorites), new { userId = favorite.user_id }, UserFavoriteDto.FromEntity(favorite));
        }
        
        [HttpDelete("favorites/{userId}/{movieId}")]
        public async Task<IActionResult> RemoveFavorite(int userId, string movieId)
        {
            var favorite = await _context.Favorites
                .FirstOrDefaultAsync(f => f.user_id == userId && f.movie_id == movieId);
                
            if (favorite == null)
            {
                return NotFound();
            }
            
            _context.Favorites.Remove(favorite);
            await _context.SaveChangesAsync();
            
            return NoContent();
        }
        
        // Watchlist endpoints
        [HttpGet("watchlist/user/{userId}")]
        public async Task<ActionResult<List<UserWatchlistDto>>> GetUserWatchlist(int userId)
        {
            var watchlistItems = await _context.Watchlist
                .Where(w => w.user_id == userId)
                .Select(w => UserWatchlistDto.FromEntity(w))
                .ToListAsync();
                
            return Ok(watchlistItems);
        }
        
        [HttpPost("watchlist")]
        public async Task<ActionResult<UserWatchlistDto>> AddToWatchlist(UserWatchlistDto watchlistDto)
        {
            // Check if this watchlist item already exists
            var existingItem = await _context.Watchlist
                .FirstOrDefaultAsync(w => w.user_id == watchlistDto.user_id && w.movie_id == watchlistDto.movie_id);
                
            if (existingItem != null)
            {
                return Ok(UserWatchlistDto.FromEntity(existingItem)); // Already exists
            }
            
            // Create new watchlist item
            var watchlistItem = new UserWatchlist
            {
                user_id = watchlistDto.user_id,
                movie_id = watchlistDto.movie_id
            };
            
            _context.Watchlist.Add(watchlistItem);
            await _context.SaveChangesAsync();
            
            return CreatedAtAction(nameof(GetUserWatchlist), new { userId = watchlistItem.user_id }, UserWatchlistDto.FromEntity(watchlistItem));
        }
        
        [HttpDelete("watchlist/{userId}/{movieId}")]
        public async Task<IActionResult> RemoveFromWatchlist(int userId, string movieId)
        {
            var watchlistItem = await _context.Watchlist
                .FirstOrDefaultAsync(w => w.user_id == userId && w.movie_id == movieId);
                
            if (watchlistItem == null)
            {
                return NotFound();
            }
            
            _context.Watchlist.Remove(watchlistItem);
            await _context.SaveChangesAsync();
            
            return NoContent();
        }
    }
}