using IdentityManager.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityManager.Data
{
    public class AppDBContext : IdentityDbContext
    {
        public AppDBContext(DbContextOptions options)
            : base(options)
        {
        }

        public DbSet<ApplicationUser> ApplicationUsers { get; set; }
    }
}
