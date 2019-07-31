using AppointmentV2.Authentication.Data;
using AppointmentV2.Authentication.Roles;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.DataProtection;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Text;
using System.Threading.Tasks;

namespace AppointmentV2.Authentication
{
    public class AppUserManager : UserManager<AppUser>
    {
        public AppUserManager(IUserStore<AppUser> store)
        : base(store)
        {
            UserValidator = new UserValidator<AppUser>(this)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = false,
            };

            PasswordValidator = new PasswordValidator()
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit = false,
                RequireDigit = false,
                RequireLowercase = false,
                RequireUppercase = false,
            };

            UserLockoutEnabledByDefault = true;
            DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
            MaxFailedAccessAttemptsBeforeLockout = 10;
        }

        public async Task<IdentityResult> CreateUserAsync(AppUser user, string password)
        {
            var result = await CreateAsync(user, password);
            if (!result.Succeeded)
                return result;

            result = await AddToRoleAsync(user.Id, AppRole.User);
            if (!result.Succeeded)
            {
                await DeleteAsync(user);
                return result;
            }
            return result;
        }

        public override async Task<IdentityResult> AddToRoleAsync(string userId, string roleName)
        {
            try
            {
                return await base.AddToRoleAsync(userId, roleName);
            }
            catch (Exception e)
            {
                var store = Store as UserStore<AppUser>;
                if (store == null)
                    return new IdentityResult("Could not convert Store");

                var roleManager = new AuthenticationRoleManager(new RoleStore<IdentityRole>(store.Context));
                var roleExists = await roleManager.RoleExistsAsync(roleName);
                if (roleExists)
                    return new IdentityResult(e.Message);

                var result = await roleManager.CreateAsync(new IdentityRole(roleName));
                if (!result.Succeeded)
                    return result;

                return await AddToRoleAsync(userId, roleName);
            }

        }

        public static AppUserManager Create(IdentityFactoryOptions<AppUserManager> options, IOwinContext context)
        {
            var manager = new AppUserManager(new UserStore<AppUser>(context.Get<AuthDbContext>()));

            IDataProtectionProvider dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider = new DataProtectorTokenProvider<AppUser>(dataProtectionProvider.Create("ASP.NET Identity"));
            }
            return manager;
        }
    }
}

