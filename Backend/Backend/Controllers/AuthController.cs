using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Linq;
using System.Collections.Generic;
using Backend.Models;
using CineNiche.API.Data;
using Microsoft.EntityFrameworkCore;
using CineNiche.API.DTOs;
using System.Security.Cryptography;

namespace Backend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthController> _logger;
        private readonly MoviesDbContext _context;
        private readonly HttpClient _httpClient;
        private readonly string _stytchProjectId;
        private readonly string _stytchSecret;

        public AuthController(
            IConfiguration configuration,
            ILogger<AuthController> logger,
            MoviesDbContext context,
            IHttpClientFactory httpClientFactory)
        {
            _configuration = configuration;
            _logger = logger;
            _context = context;
            _httpClient = httpClientFactory.CreateClient("StytchClient");
            
            // Read from configuration
            _stytchProjectId = configuration["Stytch:ProjectID"];
            _stytchSecret = configuration["Stytch:Secret"];
            
            // Configure HTTP client with basic auth using project ID and secret
            var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{_stytchProjectId}:{_stytchSecret}"));
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);
            
            // Get base URL from config or use default
            var baseUrl = configuration["Stytch:BaseUrl"] ?? "https://test.stytch.com/v1/";
            _httpClient.BaseAddress = new Uri(baseUrl);
        }

        // This endpoint will handle authentication with a Stytch token (OAuth or password)
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto request)
        {
            try
            {
                // Determine which Stytch endpoint to use based on token type
                string endpoint;
                StringContent payload;
                
                if (request.TokenType.Equals("oauth", StringComparison.OrdinalIgnoreCase))
                {
                    endpoint = "oauth/authenticate";
                    payload = new StringContent(
                        JsonSerializer.Serialize(new { token = request.Token }),
                        Encoding.UTF8,
                        "application/json");
                }
                else if (request.TokenType.Equals("session", StringComparison.OrdinalIgnoreCase))
                {
                    endpoint = "sessions/authenticate";
                    payload = new StringContent(
                        JsonSerializer.Serialize(new { session_token = request.Token }),
                        Encoding.UTF8,
                        "application/json");
                }
                else if (request.TokenType.Equals("passwords", StringComparison.OrdinalIgnoreCase))
                {
                    endpoint = "passwords/authenticate";
                    payload = new StringContent(
                        JsonSerializer.Serialize(new { 
                            password = request.Password,
                            email = request.Email
                        }),
                        Encoding.UTF8,
                        "application/json");
                }
                else
                {
                    return BadRequest(new { message = $"Unsupported token type: {request.TokenType}" });
                }
                
                // Call Stytch API
                var response = await _httpClient.PostAsync(endpoint, payload);
                var content = await response.Content.ReadAsStringAsync();
                
                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning("Stytch authentication failed: {StatusCode} - {Content}", 
                        response.StatusCode, content);
                    return Unauthorized(new { message = "Authentication failed" });
                }
                
                // Deserialize Stytch response
                var stytchResponse = JsonSerializer.Deserialize<StytchAuthResponse>(content, 
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                
                if (stytchResponse?.User == null)
                {
                    _logger.LogWarning("Stytch response did not contain user information. Content: {Content}", content);
                    return Unauthorized(new { message = "Authentication failed - invalid Stytch response" });
                }
                
                // Get user info
                string userId = stytchResponse.User.UserId;
                string email = stytchResponse.User.Emails?.FirstOrDefault(e => e.Verified)?.Email
                               ?? stytchResponse.User.Emails?.FirstOrDefault()?.Email
                               ?? stytchResponse.User.Email
                               ?? "unknown@example.com";
                
                // Find or create user in our database
                var user = await FindOrCreateUserFromStytchAsync(userId, email);
                
                // Generate a JWT token for subsequent API requests
                var token = GenerateJwtToken(user);
                
                // Return the defined LoginResponseDto
                return Ok(new LoginResponseDto
                {
                    Token = token,
                    User = user.ToUserInfoDto()
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during Stytch login");
                return StatusCode(500, new { message = "An error occurred during login" });
            }
        }

        // Optional: Endpoint to verify an existing JWT token
        [HttpPost("verify")]
        public async Task<IActionResult> VerifyToken([FromBody] VerifyTokenRequest request)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Secret"]);
                
                tokenHandler.ValidateToken(request.Token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidIssuer = _configuration["Jwt:Issuer"],
                    ValidateAudience = true,
                    ValidAudience = _configuration["Jwt:Audience"],
                    ClockSkew = TimeSpan.Zero
                }, out var validatedToken);
                
                var jwtToken = (JwtSecurityToken)validatedToken;
                var userIdClaim = jwtToken.Claims.FirstOrDefault(x => x.Type == "id");

                if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out var userId))
                {
                    _logger.LogWarning("JWT token verification failed: User ID claim ('id') missing or invalid.");
                    return Unauthorized(new { message = "Invalid token: User ID missing or invalid" });
                }
                
                var user = await _context.Users.FindAsync(userId);
                if (user == null)
                {
                    _logger.LogWarning("JWT token verification failed: User with ID {UserId} not found.", userId);
                    return Unauthorized(new { message = "Invalid token: User not found" });
                }
                
                return Ok(user.ToUserInfoDto());
            }
            catch (SecurityTokenException ex)
            {
                _logger.LogWarning(ex, "JWT token validation failed.");
                return Unauthorized(new { message = "Invalid token" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during token verification");
                return StatusCode(500, new { message = "An error occurred during token verification" });
            }
        }

        private string GenerateJwtToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Secret"]);
            
            var claims = new List<Claim>
            {
                new Claim("id", user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.NameIdentifier, user.Username ?? user.Email)
            };
            
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddDays(7),
                Issuer = _configuration["Jwt:Issuer"],
                Audience = _configuration["Jwt:Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private async Task<User> FindOrCreateUserFromStytchAsync(string stytchUserId, string email)
        {
            // Try to find User by StytchUserId first
            var movieUser = await _context.Users
                .FirstOrDefaultAsync(u => u.name == stytchUserId);  // Use name field for stytchUserId

            if (movieUser != null)
            {
                // Convert to User model
                return movieUser.ToUser();
            }

            // Then look for user by email
            movieUser = await _context.Users
                .FirstOrDefaultAsync(u => u.email == email);

            if (movieUser != null)
            {
                // Add or update stytchUserId (in name field)
                if (string.IsNullOrEmpty(movieUser.name))
                {
                    movieUser.name = stytchUserId;
                    await _context.SaveChangesAsync();
                }
                else if (movieUser.name != stytchUserId)
                {
                    _logger.LogWarning("Attempted to link Stytch ID {NewStytchUserId} to email {Email}, but it's already linked to Stytch ID {ExistingStytchUserId}.", 
                        stytchUserId, email, movieUser.name);
                    throw new InvalidOperationException($"User with email {email} is already linked to a different Stytch account.");
                }

                return movieUser.ToUser(); // Convert to User model
            }

            // Create a new user record
            var newMovieUser = new MovieUser
            {
                email = email,
                name = stytchUserId,  // Use name for StytchUserId
                phone = string.Empty,
                gender = string.Empty,
                city = string.Empty,
                state = string.Empty,
                age = 0,
                password = "stytch-auth", // Placeholder
                isAdmin = 0 // Regular user
            };

            await _context.Users.AddAsync(newMovieUser);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Created new user with ID {UserId} for Stytch ID {StytchUserId} and email {Email}.", 
                newMovieUser.user_id, stytchUserId, email);
                
            return newMovieUser.ToUser(); // Convert to User model
        }

        // New endpoint for user registration
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto request)
        {
            try
            {
                // 1. Validate Input
                if (!ModelState.IsValid)
                {
                    _logger.LogWarning("Registration failed for {Email}: Invalid model state.", request.Email);
                    return BadRequest(ModelState);
                }

                // 2. Check if user already exists
                var existingUser = await _context.Users.FirstOrDefaultAsync(u => u.email == request.Email);
                if (existingUser != null)
                {
                    _logger.LogWarning("Registration failed for {Email}: Email already exists.", request.Email);
                    return Conflict(new { message = "Email already exists" });
                }

                // 3. Try to register with Stytch first
                string stytchUserId = null;
                try
                {
                    // Try to register the user with Stytch
                    var stytchPayload = new StringContent(
                        JsonSerializer.Serialize(new
                        {
                            email = request.Email,
                            password = request.Password,
                            name = request.Username ?? request.Email.Split('@')[0]
                        }),
                        Encoding.UTF8,
                        "application/json");

                    var stytchResponse = await _httpClient.PostAsync("passwords", stytchPayload);
                    var stytchContent = await stytchResponse.Content.ReadAsStringAsync();

                    if (stytchResponse.IsSuccessStatusCode)
                    {
                        var stytchResult = JsonSerializer.Deserialize<StytchUserResponse>(stytchContent,
                            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                        
                        if (stytchResult?.UserId != null)
                        {
                            stytchUserId = stytchResult.UserId;
                            _logger.LogInformation("Successfully registered with Stytch: {StytchUserId}", stytchUserId);
                        }
                    }
                    else
                    {
                        _logger.LogWarning("Failed to register with Stytch: {StatusCode} - {Content}",
                            stytchResponse.StatusCode, stytchContent);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error during Stytch registration for {Email}", request.Email);
                }

                // 4. Hash Password
                string salt = GenerateSalt();
                string passwordHash = HashPassword(request.Password, salt);
                _logger.LogInformation("Password hashed for user {Email}", request.Email);

                // 5. Create New User Entity - use MovieUser directly
                var newMovieUser = new MovieUser
                {
                    email = request.Email,
                    name = request.Username ?? request.Email.Split('@')[0],
                    password = passwordHash, // Store the hashed password for backward compatibility
                    PasswordHash = passwordHash, // Also store in new field
                    PasswordSalt = salt, // Store salt in new field
                    StytchUserId = stytchUserId, // Store Stytch user ID
                    phone = string.Empty,
                    gender = string.Empty,
                    city = string.Empty,
                    state = string.Empty,
                    age = 0,
                    isAdmin = 0 // Default to regular user
                };

                // 6. Save User to Database
                try
                {
                    await _context.Users.AddAsync(newMovieUser);
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("Successfully registered new user with ID {UserId} and email {Email}", 
                        newMovieUser.user_id, newMovieUser.email);

                    // Convert to User model for generating JWT
                    var user = newMovieUser.ToUser();
                    
                    // 7. Generate JWT and return Success Response
                    var token = GenerateJwtToken(user);
                    
                    // Return 200 OK with LoginResponseDto
                    return Ok(new LoginResponseDto
                    {
                        User = user.ToUserInfoDto(),
                        Token = token
                    });
                }
                catch (DbUpdateException ex)
                {
                    _logger.LogError(ex, "Database error during registration for {Email}", request.Email);
                    return StatusCode(500, new { message = "An error occurred during registration (database)." });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Unexpected error during registration for {Email}", request.Email);
                    return StatusCode(500, new { message = "An unexpected error occurred during registration." });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during registration process for {Email}", request.Email);
                return StatusCode(500, new { message = "An unexpected error occurred during registration." });
            }
        }

        // Placeholder for GetUserById needed by CreatedAtAction
        // TODO: Implement this endpoint properly if needed, maybe in a separate UserController
        [HttpGet("{id}")]
        [ApiExplorerSettings(IgnoreApi = true)] // Hide from Swagger for now
        public async Task<IActionResult> GetUserById(int id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null) return NotFound();
            return Ok(user.ToUserInfoDto());
        }

        // --- Password Hashing Helpers ---

        private static string GenerateSalt(int size = 16) // 128 bit
        {
            var randomNumber = new byte[size];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
            }
            return Convert.ToBase64String(randomNumber);
        }

        private static string HashPassword(string password, string salt)
        {
            var saltBytes = Convert.FromBase64String(salt);
            using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, saltBytes, 10000, HashAlgorithmName.SHA256))
            {
                return Convert.ToBase64String(rfc2898DeriveBytes.GetBytes(32)); // 256 bit hash
            }
        }

        // Method to verify password (needed for password login)
        private static bool VerifyPassword(string enteredPassword, string storedHash, string storedSalt)
        {
            var saltBytes = Convert.FromBase64String(storedSalt);
            using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(enteredPassword, saltBytes, 10000, HashAlgorithmName.SHA256))
            {
                var hashBytes = rfc2898DeriveBytes.GetBytes(32);
                var enteredHash = Convert.ToBase64String(hashBytes);
                return enteredHash == storedHash;
            }
        }
        
        // New endpoint for direct email/password login
        [HttpPost("login-with-password")]
        public async Task<IActionResult> LoginWithPassword([FromBody] LoginPasswordDto request)
        {
            string debugStep = "start";
            
            try
            {
                _logger.LogInformation("Login attempt for email: {Email}", request.Email);
                
                debugStep = "db-query";
                var user = await _context.Users
                    .AsNoTracking()
                    .FirstOrDefaultAsync(u => u.email == request.Email);
                
                debugStep = "user-check";
                if (user == null)
                {
                    _logger.LogWarning("User not found: {Email}", request.Email);
                    return Unauthorized(new { message = "Invalid email or password" });
                }
                
                _logger.LogInformation("User found: ID={UserId}, Email={Email}", user.user_id, user.email);

                // Return early with a successful user lookup only to test database connection
                /* // REMOVE THIS DEBUG BLOCK
                return Ok(new
                {
                    token = "hard-coded-token-for-testing", 
                    user = new
                    {
                        id = user.user_id,
                        email = user.email,
                        name = user.name ?? "User",
                        isAdmin = user.isAdmin == 1
                    }
                });
                */ // END REMOVE

                // The code below this point is not executed - will be restored once we fix the issue

                // /* // REMOVE COMMENT START
                // Verify Password
                debugStep = "verify-password";
                // Ensure user has PasswordHash and PasswordSalt populated
                if (string.IsNullOrEmpty(user.PasswordHash) || string.IsNullOrEmpty(user.PasswordSalt))
                {
                    _logger.LogWarning("Password login attempt for user {UserId} failed: Missing hash or salt.", user.user_id);
                    // Optionally, attempt Stytch password auth here if StytchUserId exists?
                    // For now, treat as invalid credentials.
                    return Unauthorized(new { message = "Invalid email or password. Account may use external login." });
                }

                bool isPasswordValid = VerifyPassword(request.Password, user.PasswordHash, user.PasswordSalt);
                if (!isPasswordValid)
                {
                    _logger.LogWarning("Invalid password attempt for user: {Email}", request.Email);
                    return Unauthorized(new { message = "Invalid email or password" });
                }

                // Generate token
                debugStep = "generate-token";
                var convertedUser = user.ToUser(); // Convert MovieUser to User model
                var token = GenerateJwtToken(convertedUser);

                debugStep = "create-response";
                // Return LoginResponseDto or similar standard object
                return Ok(new LoginResponseDto
                {
                    Token = token,
                    User = convertedUser.ToUserInfoDto() // Use the UserInfoDto helper
                });
                // */ // REMOVE COMMENT END
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login-with-password at step {Step}: {Message}", debugStep, ex.Message);
                return StatusCode(500, new { 
                    message = "An error occurred during login",
                    step = debugStep,
                    error = ex.Message
                });
            }
        }

        // Debug endpoint - completely bypasses authentication
        [HttpPost("debug-login")]
        public IActionResult DebugLogin([FromBody] LoginPasswordDto request)
        {
            try
            {
                _logger.LogInformation("Debug login for email: {Email}", request.Email);
                
                // Generate fixed token
                string token = "debug-token-for-testing-only";
                
                // Return hardcoded response
                return Ok(new
                {
                    token = token,
                    user = new
                    {
                        id = 123,
                        email = request.Email,
                        name = "Debug User",
                        isAdmin = true
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in debug login: {Message}", ex.Message);
                return StatusCode(500, new { message = ex.Message });
            }
        }

        // Ultra simple test endpoint - does nothing but return a fixed response
        [HttpPost("test-endpoint")]
        public IActionResult TestEndpoint()
        {
            return Ok(new { message = "Test endpoint works!" });
        }

        // Test database connection but return hardcoded response
        [HttpPost("debug-db")]
        public async Task<IActionResult> DebugDatabase([FromBody] LoginPasswordDto request)
        {
            try 
            {
                _logger.LogInformation("Testing DB access for: {Email}", request.Email);
                
                // Just count the users to verify database connectivity
                int userCount = await _context.Users.CountAsync();
                
                // Return completely hardcoded response
                return Ok(new { 
                    message = $"Database connection successful. User count: {userCount}",
                    token = "test-token",
                    user = new { id = 1, email = "test@example.com", name = "Test User", isAdmin = false }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Database connection test failed: {Message}", ex.Message);
                return StatusCode(500, new { message = "Database error", error = ex.Message });
            }
        }
    }
}
