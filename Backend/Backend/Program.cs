using CineNiche.API.Data;
using Microsoft.EntityFrameworkCore;
using System.Text.Json.Serialization;
using System.Text.Json;
using Microsoft.Extensions.Options;
// using CineNiche.API.Models; // Ensure this is removed/commented
// using CineNiche.API.Models.Stytch; // Ensure this is removed/commented
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Backend.Models;
using CineNiche.API.DTOs;
using Microsoft.AspNetCore.HttpsPolicy;
using CineNiche.API.Services;

var builder = WebApplication.CreateBuilder(args);

// Add configuration
builder.Configuration.AddJsonFile("appsettings.json");
builder.Configuration.AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true);
builder.Configuration.AddEnvironmentVariables();

builder.Services.AddScoped<RecommendationService>(); 

// Configure Database with better path handling
var connectionString = builder.Configuration.GetConnectionString("MoviesDb");
string dbPath = connectionString;

// If we're using a relative path, ensure it's resolved correctly
if (connectionString.Contains("./") || connectionString.Contains("../"))
{
    // For relative paths, resolve against ContentRootPath
    string relativePath = connectionString.Replace("Data Source=", "");
    dbPath = $"Data Source={Path.Combine(builder.Environment.ContentRootPath, relativePath)}";
    Console.WriteLine($"Resolved database path: {dbPath}");

    // Make sure the directory exists
    string dbDir = Path.GetDirectoryName(Path.Combine(builder.Environment.ContentRootPath, relativePath));
    if (!Directory.Exists(dbDir))
    {
        Console.WriteLine($"Creating database directory: {dbDir}");
        Directory.CreateDirectory(dbDir);
    }
}
else
{
    Console.WriteLine($"Using database path as-is: {dbPath}");
}

// Add services to the container
builder.Services.AddDbContext<MoviesDbContext>(options =>
    options.UseSqlite(dbPath));

// Configure JSON serialization
builder.Services.AddControllers()
    .AddJsonOptions(options => {
        // Use camelCase for property names to match JavaScript conventions
        options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        // Include all properties in serialization
        options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
        // Enable property name case-insensitive matching for deserialization
        options.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
    });

// HTTPS configuration
builder.Services.AddHsts(options =>
{
    options.Preload = true;
    options.IncludeSubDomains = true;
    options.MaxAge = TimeSpan.FromDays(60);
});

// Add CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy.WithOrigins(
                "http://localhost:3000",  // React's default port with Create React App
                "http://localhost:5173",  // Vite's default port
                "http://127.0.0.1:3000",
                "http://127.0.0.1:5173",
                "https://localhost:3000",  // HTTPS versions
                "https://localhost:5173", 
                "https://127.0.0.1:3000",
                "https://127.0.0.1:5173",
                "https://localhost:5212",
                "https://cineniche-fkazataxamgph8bu.eastus-01.azurewebsites.net" // Azure domain
            )
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

// Configure Stytch
builder.Services.Configure<StytchConfig>(builder.Configuration.GetSection("Stytch"));

// Register the HttpClient named "StytchClient" 
builder.Services.AddHttpClient<IStytchClient, StytchClient>();

// Add JWT Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Secret"]))
    };
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
else
{
    // In production, use HSTS
    app.UseHsts();
}

// Add Content-Security-Policy middleware
app.Use(async (context, next) =>
{
    // Define CSP policies
    context.Response.Headers.Add("Content-Security-Policy", 
        "default-src 'self';" +
        "img-src 'self' https://postersintex.blob.core.windows.net data:;" +
        "style-src 'self' https://fonts.googleapis.com 'unsafe-inline';" +
        "font-src 'self' https://fonts.gstatic.com;" +
        "script-src 'self' 'unsafe-inline';" + 
        "connect-src 'self' https://localhost:* http://localhost:*;" +
        "frame-ancestors 'none';" +
        "form-action 'self';" +
        "base-uri 'self';" +
        "object-src 'none'");

    // Add other security headers
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Add("Permissions-Policy", "camera=(), microphone=(), geolocation=()");

    await next();
});

// Use CORS before any other middleware
app.UseCors("AllowFrontend");

// Re-enable HTTPS redirection
app.UseHttpsRedirection();

// Add authentication middleware before authorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.Run();
