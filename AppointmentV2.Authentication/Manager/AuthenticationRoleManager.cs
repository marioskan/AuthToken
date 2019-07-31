using AppointmentV2.Authentication.Data;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AppointmentV2.Authentication.Roles
{
    public class AuthenticationRoleManager : RoleManager<IdentityRole>
    {
        public AuthenticationRoleManager(IRoleStore<IdentityRole, string> roleStore)
            : base(roleStore)
        {
        }

        public static AuthenticationRoleManager Create(IdentityFactoryOptions<AuthenticationRoleManager> options, IOwinContext context)
        {
            var manager = new AuthenticationRoleManager(new RoleStore<IdentityRole>(context.Get<AuthDbContext>()));

            return manager;
        }
    }
}
