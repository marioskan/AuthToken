using AppointmentV2.Authentication;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Text;

namespace AppointmentV2.Authentication.Data
{
    public class AuthDbContext : IdentityDbContext<AppUser>
    {
        
        public AuthDbContext() : base("AuthenticationString")
        {

        }

        public static AuthDbContext Create()
        {
            return new AuthDbContext();
        }

        protected override void OnModelCreating(DbModelBuilder builder)
        {
            base.OnModelCreating(builder);
        }
    }
}
