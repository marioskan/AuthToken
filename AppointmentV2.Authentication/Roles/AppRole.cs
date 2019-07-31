using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Text;

namespace AppointmentV2.Authentication
{
    public class AppRole : IdentityRole
    {
        public AppRole() : base() { }
        public AppRole(string name) : base(name) { }

        public const string Admin = "Admin";
        public const string Doctor = "Doctor";
        public const string User = "User";
    }
}
