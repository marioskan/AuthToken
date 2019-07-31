using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace AppointmentV2.Authentication.Providers
{
    public class OAuthAccessTokenProvider : OAuthAuthorizationServerProvider
    {
        private readonly string _publicClientId;

        public OAuthAccessTokenProvider(string publicClientId)
        {
            if (String.IsNullOrEmpty(publicClientId))
            {
                throw new ArgumentNullException("publicClientId");
            }
            else
            {
                _publicClientId = publicClientId;

            }

        }

        public override async Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var userManager = context.OwinContext.GetUserManager<AppUserManager>();

            AppUser user = await userManager.FindByNameAsync(context.Ticket.Identity.Name);
            if (user == null)
            {
                context.SetError("invalid_grant", "Refresh token is issued to a different account.");
                return;
            }
            AuthenticationTicket ticket = await CreateTicketAsync(userManager, user);
            context.Validated(ticket);
        }

        public static async Task<AuthenticationTicket> CreateTicketAsync(AppUserManager userManager, AppUser user)
        {
            ClaimsIdentity oAuthIdentity = await CreateIdentityClaimAsync(userManager, user);

            List<Claim> roles = oAuthIdentity.Claims.Where(c => c.Type == ClaimTypes.Role).ToList();
            AuthenticationProperties properties = CreateProperties(roles, user.UserName);
            AuthenticationTicket ticket = new AuthenticationTicket(oAuthIdentity, properties);

            return ticket;
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            var userManager = context.OwinContext.GetUserManager<AppUserManager>();

            AppUser user = await userManager.FindByNameAsync(context.UserName);
            if (user == null)
            {
                context.SetError("invalid_grant", "Wrong username or password."); //user not found
                return;
            }
            if (await userManager.IsLockedOutAsync(user.Id))
            {
                context.SetError("locked_out", "User is locked out"); // account locked out
                return;
            }

            var validCredentials = await userManager.CheckPasswordAsync(user, context.Password);
            if (!validCredentials)
            {
                await userManager.AccessFailedAsync(user.Id);
                context.SetError("invalid_grant", "Wrong username or password."); //wrong password
                return;
            }
            await userManager.ResetAccessFailedCountAsync(user.Id);

            AuthenticationTicket ticket = await CreateTicketAsync(userManager, user);
            context.Validated(ticket);
        }

        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            return Task.FromResult<object>(null);
        }

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            // Resource owner password credentials does not provide a client ID.
            if (context.ClientId == null)
            {
                context.Validated();
            }

            return Task.FromResult<object>(null);
        }


        public override Task AuthorizationEndpointResponse(OAuthAuthorizationEndpointResponseContext context)
        {
            IDictionary<string, string> propertiesDictionary = context.OwinContext.Authentication.AuthenticationResponseGrant.Properties.Dictionary;

            string refreshToken = String.Empty;
            if (!propertiesDictionary.TryGetValue("refreshToken", out refreshToken))
                refreshToken = "not_generated";

            string roles = String.Empty;
            if (!propertiesDictionary.TryGetValue("roles", out roles))
                roles = "[]";

            if (!String.IsNullOrEmpty(refreshToken))
                context.AdditionalResponseParameters.Add("refresh_token", refreshToken);

            if (!String.IsNullOrEmpty(roles))
                context.AdditionalResponseParameters.Add("roles", roles);

            return base.AuthorizationEndpointResponse(context);
        }

        public static AuthenticationProperties CreateProperties(List<Claim> userRoles, string userName)
        {
            IDictionary<string, string> data = new Dictionary<string, string>
            {
                { "userName", userName },
                { "roles", Newtonsoft.Json.JsonConvert.SerializeObject(userRoles.Select(r => r.Value)) }
            };
            return new AuthenticationProperties(data);
        }

        public static AuthenticationProperties CreateProperties(string refreshToken, List<Claim> userRoles)
        {
            IDictionary<string, string> data = new Dictionary<string, string>
            {
                { "refreshToken", refreshToken },
                { "roles", Newtonsoft.Json.JsonConvert.SerializeObject(userRoles.Select(r => r.Value)) }
            };
            return new AuthenticationProperties(data);
        }

        public static async Task<ClaimsIdentity> CreateIdentityClaimAsync(AppUserManager userManager, AppUser user)
        {
            ClaimsIdentity oAuthIdentity = await userManager.CreateIdentityAsync(user, OAuthDefaults.AuthenticationType);
            return oAuthIdentity;
        }

        public static string GenerateRandomState(int strengthInBits)
        {
            RandomNumberGenerator random = new RNGCryptoServiceProvider();
            int bitsPerByte = 8;

            if (strengthInBits % bitsPerByte != 0)
            {
                throw new ArgumentException("strengthInBits must be evenly divisible by 8.", "strengthInBits");
            }

            int strengthInBytes = strengthInBits / bitsPerByte;

            byte[] data = new byte[strengthInBytes];
            random.GetBytes(data);
            return HttpServerUtility.UrlTokenEncode(data);
        }

       
    }
}
