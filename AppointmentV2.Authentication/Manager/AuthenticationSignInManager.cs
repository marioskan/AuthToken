using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace AppointmentV2.Authentication.Manager
{
    
        public class AuthenticationSignInManager : SignInManager<AppUser, string>
        {
            public AuthenticationSignInManager(AppUserManager userManager, IAuthenticationManager authenticationManager)
                : base(userManager, authenticationManager)
            {
            }

            public override Task<ClaimsIdentity> CreateUserIdentityAsync(AppUser user)
            {
                return user.GenerateUserIdentityAsync((AppUserManager)UserManager, DefaultAuthenticationTypes.ApplicationCookie);
            }

            public static AuthenticationSignInManager Create(IdentityFactoryOptions<AuthenticationSignInManager> options, IOwinContext context)
            {
                return new AuthenticationSignInManager(context.GetUserManager<AppUserManager>(), context.Authentication);
            }
        }
    
}
