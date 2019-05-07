using System;
using System.Configuration;
using System.Configuration.Provider;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Data.Common;
using System.Diagnostics;
using System.Globalization;
using System.Text.RegularExpressions;
using System.Xml.XPath;
using System.Web;
using System.Web.Security;
using MyCompany.Data;

namespace MyCompany.Security
{
	public partial class ApplicationRoleProvider : ApplicationRoleProviderBase
    {
    }
    
    public class ApplicationRoleProviderBase : RoleProvider
    {
        
        private ConnectionStringSettings _connectionStringSettings;
        
        private bool _writeExceptionsToEventLog;
        
        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _applicationName;
        
        public virtual ConnectionStringSettings ConnectionStringSettings
        {
            get
            {
                return _connectionStringSettings;
            }
        }
        
        public bool WriteExceptionsToEventLog
        {
            get
            {
                return _writeExceptionsToEventLog;
            }
        }
        
        public override string ApplicationName
        {
            get
            {
                return this._applicationName;
            }
            set
            {
                this._applicationName = value;
            }
        }
        
        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null)
            	throw new ArgumentNullException("config");
            if (String.IsNullOrEmpty(name))
            	name = "MyCompanyApplicationRoleProvider";
            if (String.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "MyCompany application role provider");
            }
            base.Initialize(name, config);
            _applicationName = config["applicationName"];
            if (String.IsNullOrEmpty(_applicationName))
            	_applicationName = System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath;
            _writeExceptionsToEventLog = "true".Equals(config["writeExceptionsToEventLog"], StringComparison.CurrentCulture);
            _connectionStringSettings = ConfigurationManager.ConnectionStrings[config["connectionStringName"]];
            if ((_connectionStringSettings == null) || String.IsNullOrEmpty(_connectionStringSettings.ConnectionString))
            	throw new ProviderException("Connection string cannot be blank.");
        }
        
        public override void AddUsersToRoles(string[] usernames, string[] rolenames)
        {
        }
        
        public override void CreateRole(string rolename)
        {
        }
        
        public override bool DeleteRole(string rolename, bool throwOnPopulatedRole)
        {
            return false;
        }
        
        public override string[] GetAllRoles()
        {
            return new string[] {
                    "Administrators",
                    "Users"};
        }
        
        public override string[] GetRolesForUser(string username)
        {
            username = username.ToLower();
            if (username == "mpaul")
            	return new string[] {
                        "Administrators",
                        "Users"};
            return new string[] {
                    "Users"};
        }
        
        public override string[] GetUsersInRole(string rolename)
        {
            rolename = rolename.ToLower();
            if (rolename == "administrators")
            	return new string[] {
                        "mpaul"};
            if (rolename == "users")
            	return new string[] {
                        "mpaul"};
            return new string[0];
        }
        
        public override bool IsUserInRole(string username, string rolename)
        {
            rolename = rolename.ToLower();
            username = username.ToLower();
            if (rolename == "administrators")
            	return !((Array.IndexOf(new string[] {
                                        "mpaul"}, username) == -1));
            if (rolename == "users")
            	return true;
            return false;
        }
        
        public override void RemoveUsersFromRoles(string[] usernames, string[] rolenames)
        {
        }
        
        public override bool RoleExists(string rolename)
        {
            return !((Array.IndexOf(GetAllRoles(), rolename) == -1));
        }
        
        public override string[] FindUsersInRole(string rolename, string usernameToMatch)
        {
            return new string[0];
        }
    }
}
