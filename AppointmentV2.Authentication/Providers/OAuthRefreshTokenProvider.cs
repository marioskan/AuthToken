using AppointmentV2.Authentication.Data;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace AppointmentV2.Authentication.Providers
{
   
        public class OAuthRefreshTokenProvider : IAuthenticationTokenProvider
        {
            public void Create(AuthenticationTokenCreateContext context)
            {
                AuthenticationTicket ticket = context.Ticket;

                IEnumerable<Claim> test = ticket.Identity.Claims;

                using (var appIdentityDbContext = new AuthDbContext())
                {
                    AppUser user = appIdentityDbContext.Users
                                                    .FirstOrDefault(u => u.UserName == ticket.Identity.Name);

                    if (user == null)
                        return;

                    int refreshTokenExpirationInDays = 300;
                    ticket.Properties.ExpiresUtc = DateTime.UtcNow.AddDays(refreshTokenExpirationInDays);

                    context.SetToken(context.SerializeTicket());
                }
            }

            public void Receive(AuthenticationTokenReceiveContext context)
            {
                context.DeserializeTicket(context.Token);
                AuthenticationTicket ticket = context.Ticket;

                if (ticket == null)
                {
                    context.Response.StatusCode = 400;
                    context.Response.ReasonPhrase = "invalidToken";
                    return;
                }

                using (var appIdentityDbContext = new AuthDbContext())
                {
                    AppUser user = appIdentityDbContext.Users
                                                    .FirstOrDefault(u => u.UserName == ticket.Identity.Name);

                    if (user == null)
                    {
                        context.Response.StatusCode = 400;
                        context.Response.ReasonPhrase = "unableToFindUser";

                        context.DeserializeTicket(String.Empty);
                        return;
                    }
                }

                context.SetTicket(context.Ticket);
            }

            public async Task CreateAsync(AuthenticationTokenCreateContext context)
            {
                Create(context);
            }

            public async Task ReceiveAsync(AuthenticationTokenReceiveContext context)
            {
                Receive(context);
            }
        }
    
}
