using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AppointmentV2.Authentication.Configuration
{
    public class UserConfigurationManager
    {
        public static bool FixedConfirmationCode
        {
            get
            {
                return true;
            }
        }
        public static int AccessTokenExpirationInMinutes
        {
            get
            {
                return 300;
            }
        }
    }
}
