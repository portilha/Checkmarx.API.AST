using System;

namespace Checkmarx.API.AST
{
    public class Client
    {
        public string Tenant { get; }

        public string Username { get; set; }

        public string Password { get; set; }

        public Client(string tenant, string username, string password)
        {
            if(string.IsNullOrWhiteSpace(tenant)) throw new ArgumentNullException(nameof(tenant));
            if(string.IsNullOrWhiteSpace(username)) throw new ArgumentNullException(nameof(username));
            if(string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));
            
            Tenant = tenant;
            Username = username; 
            Password = password;   
        }
        
    }
}
