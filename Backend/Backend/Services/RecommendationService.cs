// RecommendationService.cs
using System;
using System.Collections.Generic;
using System.Linq;
using CineNiche.API.Data;
using Microsoft.EntityFrameworkCore;

namespace CineNiche.API.Services
{
    public class RecommendationService
    {
        private readonly MoviesDbContext _context;

        public RecommendationService(MoviesDbContext context)
        {
            _context = context;
        }

        // Content-based filtering
        public async Task<List<MovieTitle>> GetContentBasedRecommendations(string showId, int count = 5)
        {
            var targetMovie = await _context.Movies.FindAsync(showId);
            if (targetMovie == null) return new List<MovieTitle>();

            // Get all movies except the target
            var allMovies = await _context.Movies
                .Where(m => m.show_id != showId)
                .ToListAsync();

            // Calculate similarity based on genres
            var targetCategories = targetMovie.ActiveCategories;
            var similarMovies = allMovies
                .Select(m => new
                {
                    Movie = m,
                    SimilarityScore = CalculateGenreSimilarity(targetCategories, m.ActiveCategories)
                })
                .OrderByDescending(x => x.SimilarityScore)
                .Take(count)
                .Select(x => x.Movie)
                .ToList();

            return similarMovies;
        }

        private double CalculateGenreSimilarity(List<string> genres1, List<string> genres2)
        {
            if (!genres1.Any() || !genres2.Any()) return 0;

            var intersection = genres1.Intersect(genres2).Count();
            var union = genres1.Union(genres2).Count();

            return union == 0 ? 0 : (double)intersection / union;
        }

        // Hybrid recommendation combining content-based and user behavior
        public async Task<List<MovieTitle>> GetHybridRecommendations(string showId, int? userId = null, int count = 5)
        {
            var contentBased = await GetContentBasedRecommendations(showId, count * 2);

            // If we have a user, incorporate their preferences
            if (userId.HasValue)
            {
                var userRatings = await _context.Ratings
                    .Where(r => r.user_id == userId)
                    .ToListAsync();

                // Simple collaborative filtering - boost movies liked by this user
                var ratedMovieIds = userRatings.Select(r => r.show_id).ToList();
                contentBased = contentBased
                    .OrderByDescending(m =>
                        ratedMovieIds.Contains(m.show_id) ? 1 : 0)
                    .Take(count)
                    .ToList();
            }

            return contentBased.Take(count).ToList();
        }
    }
}