using IdentityManager;
using IdentityManager.Authorize;
using IdentityManager.Data;
using IdentityManager.Models;
using IdentityManager.Services;
using IdentityManager.Services.IServices;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Drawing.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddDbContext<AppDBContext>(options =>
options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<AppDBContext>()
    .AddDefaultTokenProviders();

builder.Services.AddScoped<IEmailSender, EmailSender>();

builder.Services.AddScoped<INumberOfDaysForAccount, NumberOfDaysForAccount>();
builder.Services.AddScoped<IAuthorizationHandler, Sudo1KHandler>();
builder.Services.AddScoped<IAuthorizationHandler, FirstNameHandler>();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.AccessDeniedPath = "/Account/NoAccess";
});

builder.Services.Configure<IdentityOptions>(options =>
{
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.SignIn.RequireConfirmedEmail = false;
});
builder.Services.AddAuthorization(opt =>
{
    opt.AddPolicy("AdminRole_Sudo", policy => policy.RequireAssertion(context => (
        AdminRole_Sudo(context)
    )));
    opt.AddPolicy("Admin", policy => policy.RequireRole(SD.Admin));
    opt.AddPolicy("AdminAndUser", policy => policy.RequireRole(SD.Admin).RequireRole(SD.User));
    opt.AddPolicy("AdminRole_CreateClaim", policy => policy.RequireRole(SD.Admin).RequireClaim("Create", "True"));
    opt.AddPolicy("AdminRole_AllClaims", policy => policy
            .RequireRole(SD.Admin)
            .RequireClaim("Create", "True")
            .RequireClaim("Edit", "True")
            .RequireClaim("Delete", "True")
        );
    opt.AddPolicy("OnlySudoAdminChecker", policy => policy.Requirements.Add(new OnlySudoAdminChecker()));
    opt.AddPolicy("Sudo1K", policy => policy.Requirements.Add(new Sudo1K(1000)));
    opt.AddPolicy("FirstNameAuth", p => p.Requirements.Add(new FirstNameRequirement("leo")));
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

bool AdminRole_Sudo(AuthorizationHandlerContext context)
{
    return (
        context.User.IsInRole(SD.Admin) &&
        context.User.HasClaim(c => c.Type == "Create" && c.Value == "True") &&
        context.User.HasClaim(c => c.Type == "Edit" && c.Value == "True") &&
        context.User.HasClaim(c => c.Type == "Delete" && c.Value == "True")
        )
        || context.User.IsInRole(SD.Admin_Sudo);
}

